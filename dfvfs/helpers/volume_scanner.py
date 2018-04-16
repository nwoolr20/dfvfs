# -*- coding: utf-8 -*-
"""Volume scanners."""

from __future__ import unicode_literals

import abc
import os

from dfvfs.credentials import manager as credentials_manager
from dfvfs.lib import definitions
from dfvfs.lib import errors
from dfvfs.helpers import source_scanner
from dfvfs.helpers import windows_path_resolver
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver
from dfvfs.volume import tsk_volume_system
from dfvfs.volume import vshadow_volume_system


class VolumeScannerMediator(object):
  """Volume scanner mediator."""

  @abc.abstractmethod
  def GetPartitionIdentifiers(self, volume_system, volume_identifiers):
    """Retrieves partition identifiers.

    This method can be used to prompt the user to provide partition identifiers.

    Args:
      volume_system (TSKVolumeSystem): volume system.
      volume_identifiers (list[str]): volume identifiers.

    Returns:
      list[str]: selected partition identifiers, such as "p1", or None.

    Raises:
      ScannerError: if the source cannot be processed.
    """

  @abc.abstractmethod
  def GetVSSStoreIdentifiers(self, volume_system, volume_identifiers):
    """Retrieves VSS store identifiers.

    This method can be used to prompt the user to provide VSS store identifiers.

    Args:
      volume_system (VShadowVolumeSystem): volume system.
      volume_identifiers (list[str]): volume identifiers.

    Returns:
      list[int]: selected VSS store numbers or None.

    Raises:
      ScannerError: if the source cannot be processed.
    """

  @abc.abstractmethod
  def UnlockEncryptedVolume(
      self, source_scanner_object, scan_context, locked_scan_node, credentials):
    """Unlocks an encrypted volume.

    This method can be used to prompt the user to provide encrypted volume
    credentials.

    Args:
      source_scanner_object (SourceScanner): source scanner.
      scan_context (SourceScannerContext): source scanner context.
      locked_scan_node (SourceScanNode): locked scan node.
      credentials (Credentials): credentials supported by the locked scan node.

    Returns:
      bool: True if the volume was unlocked.
    """


class VolumeScanner(object):
  """Volume scanner."""

  def __init__(self, mediator=None):
    """Initializes a volume scanner.

    Args:
      mediator (VolumeScannerMediator): a volume scanner mediator.
    """
    super(VolumeScanner, self).__init__()
    self._credentials = []
    self._credential_configurations = []
    self._mediator = mediator
    self._source_path = None
    self._source_scanner = source_scanner.SourceScanner()
    self._source_type = None
    self._vss_stores = None

  def _AddCredentialConfiguration(
      self, path_spec, credential_type, credential_data):
    """Adds a credential configuration.

    Args:
      path_spec (dfvfs.PathSpec): path specification.
      credential_type (str): credential type.
      credential_data (bytes): credential data.
    """
    credential_configuration = configurations.CredentialConfiguration(
        credential_data=credential_data, credential_type=credential_type,
        path_spec=path_spec)

    self._credential_configurations.append(credential_configuration)

  def _GetNormalizedTSKVolumeIdentifiers(
      self, volume_system, volume_identifiers):
    """Retrieves the normalized TSK volume identifiers.

    Args:
      volume_system (dfvfs.TSKVolumeSystem): volume system.
      volume_identifiers (list[str]): allowed volume identifiers.

    Returns:
      list[int]: normalized volume identifiers.
    """
    normalized_volume_identifiers = []
    for volume_identifier in volume_identifiers:
      volume = volume_system.GetVolumeByIdentifier(volume_identifier)
      if not volume:
        raise errors.SourceScannerError(
            'Volume missing for identifier: {0:s}.'.format(volume_identifier))

      try:
        volume_identifier = int(volume.identifier[1:], 10)
        normalized_volume_identifiers.append(volume_identifier)
      except ValueError:
        pass

    return normalized_volume_identifiers

  def _GetNormalizedVShadowVolumeIdentifiers(
      self, volume_system, volume_identifiers):
    """Retrieves the normalized VShadow volume identifiers.

    Args:
      volume_system (dfvfs.VShadowVolumeSystem): volume system.
      volume_identifiers (list[str]): allowed volume identifiers.

    Returns:
      list[int]: normalized volume identifiers.
    """
    normalized_volume_identifiers = []
    for volume_identifier in volume_identifiers:
      volume = volume_system.GetVolumeByIdentifier(volume_identifier)
      if not volume:
        raise errors.SourceScannerError(
            'Volume missing for identifier: {0:s}.'.format(volume_identifier))

      try:
        volume_identifier = int(volume.identifier[3:], 10)
        normalized_volume_identifiers.append(volume_identifier)
      except ValueError:
        pass

    return normalized_volume_identifiers

  # TODO: refactor this method that it become more clear what it is
  # supposed to do.
  def _GetTSKPartitionIdentifiers(
      self, scan_node, partition_offset=None, partitions=None):
    """Determines the TSK partition identifiers.

    This method first checks for the preferred partition number, then for
    the preferred partition offset and falls back to prompt the user if
    no usable preferences were specified.

    Args:
      scan_node (dfvfs.SourceScanNode): scan node.
      partition_offset (Optional[int]): preferred partition byte offset.
      partitions (Optional[list[str]]): preferred partition identifiers.

    Returns:
      list[str]: partition identifiers.

    Raises:
      RuntimeError: if the volume for a specific identifier cannot be
          retrieved.
      ScannerError: if the format of or within the source
          is not supported or the the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise errors.ScannerError('Invalid scan node.')

    volume_system = tsk_volume_system.TSKVolumeSystem()
    volume_system.Open(scan_node.path_spec)

    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      self._output_writer.Write('[WARNING] No partitions found.\n')
      return None

    normalized_volume_identifiers = self._GetNormalizedTSKVolumeIdentifiers(
        volume_system, volume_identifiers)

    if partitions:
      if partitions == ['all']:
        partitions = range(1, volume_system.number_of_volumes + 1)

      if not set(partitions).difference(normalized_volume_identifiers):
        return [
            'p{0:d}'.format(partition_number)
            for partition_number in partitions]

    if partition_offset is not None:
      for volume in volume_system.volumes:
        volume_extent = volume.extents[0]
        if volume_extent.offset == partition_offset:
          return [volume.identifier]

      self._output_writer.Write((
          '[WARNING] No such partition with offset: {0:d} '
          '(0x{0:08x}).\n').format(partition_offset))

    if len(volume_identifiers) == 1:
      return volume_identifiers

    try:
      selected_volume_identifiers = (
          self._mediator.PromptUserForPartitionIdentifiers(
              volume_system, volume_identifiers))
    except KeyboardInterrupt:
      raise errors.UserAbort('File system scan aborted.')

    if selected_volume_identifiers == 'all':
      return volume_identifiers

    return [selected_volume_identifiers]

  def _GetVSSStoreIdentifiers(self, scan_node, vss_stores=None):
    """Determines the VSS store identifiers.

    Args:
      scan_node (dfvfs.SourceScanNode): scan node.
      vss_stores (Optional[list[str]]): preferred VSS store identifiers.

    Returns:
      list[str] VSS store identifiers.

    Raises:
      ScannerError: if the format of or within the source
          is not supported or the the scan node is invalid.
    """
    if not scan_node or not scan_node.path_spec:
      raise errors.ScannerError('Invalid scan node.')

    volume_system = vshadow_volume_system.VShadowVolumeSystem()
    volume_system.Open(scan_node.path_spec)

    volume_identifiers = self._source_scanner.GetVolumeIdentifiers(
        volume_system)
    if not volume_identifiers:
      return []

    try:
      selected_store_identifiers = (
          self._mediator.PromptUserForVSSStoreIdentifiers(
              volume_system, volume_identifiers, vss_stores=vss_stores))
    except KeyboardInterrupt:
      raise errors.UserAbort('File system scan aborted.')

    return selected_store_identifiers

  def _ScanFileSystem(self, file_system_scan_node, base_path_specs):
    """Scans a file system scan node for file systems.

    Args:
      file_system_scan_node (SourceScanNode): file system scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      ScannerError: if the scan node is invalid.
    """
    if not file_system_scan_node or not file_system_scan_node.path_spec:
      raise errors.ScannerError('Invalid or missing file system scan node.')

    base_path_specs.append(file_system_scan_node.path_spec)

  def _ScanVolume(self, scan_context, volume_scan_node, base_path_specs):
    """Scans the volume scan node for volume and file systems.

    Args:
      scan_context (SourceScannerContext): source scanner context.
      volume_scan_node (SourceScanNode): volume scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      ScannerError: if the format of or within the source
          is not supported or the scan node is invalid.
    """
    if not volume_scan_node or not volume_scan_node.path_spec:
      raise errors.ScannerError('Invalid or missing volume scan node.')

    if not volume_scan_node.sub_nodes:
      self._ScanVolumeScanNode(scan_context, volume_scan_node, base_path_specs)

    else:
      # Some volumes contain other volume or file systems e.g. BitLocker ToGo
      # has an encrypted and unencrypted volume.
      for sub_scan_node in volume_scan_node.sub_nodes:
        self._ScanVolumeScanNode(scan_context, sub_scan_node, base_path_specs)

  def _ScanVolumeScanNode(
      self, scan_context, volume_scan_node, base_path_specs,
      selected_vss_stores=None, vss_only=False):
    """Scans an individual volume scan node for volume and file systems.

    Args:
      scan_context (SourceScannerContext): source scanner context.
      volume_scan_node (SourceScanNode): volume scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.
      selected_vss_stores (Optional[list[str]]): selected VSS store identifiers.
      vss_only (Optional[bool]): True if only VSS should be scanned.

    Raises:
      ScannerError: if the format of or within the source
          is not supported or the scan node is invalid.
    """
    if not volume_scan_node or not volume_scan_node.path_spec:
      raise errors.ScannerError('Invalid or missing volume scan node.')

    # Get the first node where where we need to decide what to process.
    scan_node = volume_scan_node
    while len(scan_node.sub_nodes) == 1:
      # Make sure that we prompt the user about VSS selection.
      if scan_node.type_indicator == definitions.TYPE_INDICATOR_VSHADOW:
        location = getattr(scan_node.path_spec, 'location', None)
        if location == '/':
          break

      scan_node = scan_node.sub_nodes[0]

    # The source scanner found an encrypted volume and we need
    # a credential to unlock the volume.
    if scan_node.type_indicator in definitions.ENCRYPTED_VOLUME_TYPE_INDICATORS:
      self._ScanVolumeScanNodeEncrypted(
          scan_context, scan_node, base_path_specs)

    elif scan_node.type_indicator == definitions.TYPE_INDICATOR_VSHADOW:
      self._ScanVolumeScanNodeVSS(
          scan_node, base_path_specs, selected_vss_stores=selected_vss_stores,
          vss_only=vss_only)

    elif scan_node.type_indicator in definitions.FILE_SYSTEM_TYPE_INDICATORS:
      if not vss_only or not selected_vss_stores or (
          self._mediator and self._mediator.PromptUserForVSSCurrentVolume()):
        # TODO: determine if this is needed.
        # self._ScanFileSystem(scan_node, base_path_specs)
        base_path_specs.append(scan_node.path_spec)

  def _ScanVolumeScanNodeEncrypted(
      self, scan_context, volume_scan_node, base_path_specs):
    """Scans an encrypted volume scan node for volume and file systems.

    Args:
      scan_context (SourceScannerContext): source scanner context.
      volume_scan_node (SourceScanNode): volume scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      ScannerError: if the scan node is invalid.
    """
    if not volume_scan_node or not volume_scan_node.path_spec:
      raise errors.ScannerError('Invalid or missing volume scan node.')

    result = not scan_context.IsLockedScanNode(volume_scan_node.path_spec)
    if not result:
      credentials = credentials_manager.CredentialsManager.GetCredentials(
          volume_scan_node.path_spec)

      result = False
      for credential_type, credential_data in self._credentials:
        if credential_type not in credentials.CREDENTIALS:
          continue

        result = self._source_scanner.Unlock(
            scan_context, volume_scan_node.path_spec, credential_type,
            credential_data)

        if result:
          self._AddCredentialConfiguration(
              volume_scan_node.path_spec, credential_type, credential_data)
          break

      if self._credentials and not result:
        # TODO: consider raising an exception
        self._mediator.WarnUserForUnableUnlockEncryptedVolume()

      if not result:
        result = self._mediator.PromptUserForEncryptedVolumeCredential(
            scan_context, volume_scan_node, credentials)

    if result:
      self._source_scanner.Scan(
          scan_context, scan_path_spec=volume_scan_node.path_spec)
      self._ScanVolume(scan_context, volume_scan_node, base_path_specs)

  def _ScanVolumeScanNodeVSS(
      self, volume_scan_node, base_path_specs, selected_vss_stores=None):
    """Scans a VSS volume scan node for volume and file systems.

    Args:
      volume_scan_node (SourceScanNode): volume scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.
      selected_vss_stores (Optional[list[str]]): selected VSS store identifiers.

    Raises:
      ScannerError: if a VSS sub scan node scannot be retrieved or
          if the scan node is invalid.
    """
    if not volume_scan_node or not volume_scan_node.path_spec:
      raise errors.ScannerError('Invalid or missing volume scan node.')

    # Do not scan inside individual VSS store scan nodes.
    location = getattr(volume_scan_node.path_spec, 'location', None)
    if location != '/':
      return

    # TODO: vss_stores=self._vss_stores
    vss_store_identifiers = self._GetVSSStoreIdentifiers(
        volume_scan_node, vss_stores=self._vss_stores)

    selected_vss_stores.extend(vss_store_identifier)

    self._vss_stores = list(vss_store_identifiers)

    # Process VSS stores starting with the most recent one.
    vss_store_identifiers.reverse()
    for vss_store_identifier in vss_store_identifiers:
      location = '/vss{0:d}'.format(vss_store_identifier)
      sub_scan_node = volume_scan_node.GetSubNodeByLocation(location)
      if not sub_scan_node:
        raise errors.ScannerError(
            'Scan node missing for VSS store identifier: {0:d}.'.format(
                vss_store_identifier))

      # We "optimize" here for user experience, alternatively we could scan for
      # a file system instead of hard coding a TSK child path specification.
      path_spec = path_spec_factory.Factory.NewPathSpec(
          definitions.TYPE_INDICATOR_TSK, location='/',
          parent=sub_scan_node.path_spec)
      base_path_specs.append(path_spec)

      # TODO: look into building VSS store on demand.
      # self._source_scanner.Scan(
      #     scan_context, scan_path_spec=sub_scan_node.path_spec)
      # self._ScanFileSystem(sub_scan_node, base_path_specs)

  def GetBasePathSpecs(
      self, source_path, partition_offset=None, partitions=None):
    """Determines the base path specifications.

    Args:
      source_path (str): source path.
      partition_offset (Optional[int]): preferred partition byte offset.
      partitions (Optional[list[str]]): preferred partition identifiers.

    Returns:
      list[PathSpec]: path specifications.

    Raises:
      ScannerError: if the source path does not exists, or if the source path
          is not a file or directory, or if the format of or within the source
          file is not supported.
    """
    if not source_path:
      raise errors.ScannerError('Invalid source path.')

    # Symbolic links are resolved here and not earlier to preserve the user
    # specified source path in storage and reporting.
    if os.path.islink(source_path):
      source_path = os.path.realpath(source_path)

    # Note that os.path.exists() does not support Windows device paths.
    if (not source_path.startswith('\\\\.\\') and
        not os.path.exists(source_path)):
      raise errors.ScannerError(
          'No such device, file or directory: {0:s}.'.format(source_path))

    scan_context = source_scanner.SourceScannerContext()
    scan_context.OpenSourcePath(source_path)

    try:
      self._source_scanner.Scan(scan_context)
    except (ValueError, errors.BackEndError) as exception:
      raise errors.ScannerError(
          'Unable to scan source with error: {0!s}.'.format(exception))

    self._source_path = source_path
    self._source_type = scan_context.source_type

    if self._source_type not in [
        definitions.SOURCE_TYPE_STORAGE_MEDIA_DEVICE,
        definitions.SOURCE_TYPE_STORAGE_MEDIA_IMAGE]:
      scan_node = scan_context.GetRootScanNode()
      return [scan_node.path_spec]

    # Get the first node where where we need to decide what to process.
    scan_node = scan_context.GetRootScanNode()
    while len(scan_node.sub_nodes) == 1:
      scan_node = scan_node.sub_nodes[0]

    # The source scanner found a partition table and we need to determine
    # which partition needs to be processed.
    if scan_node.type_indicator != definitions.TYPE_INDICATOR_TSK_PARTITION:
      partition_identifiers = None

    else:
      partition_identifiers = self._GetTSKPartitionIdentifiers(
          scan_node, partition_offset=partition_offset, partitions=partitions)

    base_path_specs = []
    if not partition_identifiers:
      self._ScanVolume(scan_context, scan_node, base_path_specs)

    else:
      for partition_identifier in partition_identifiers:
        location = '/{0:s}'.format(partition_identifier)
        sub_scan_node = scan_node.GetSubNodeByLocation(location)
        self._ScanVolume(scan_context, sub_scan_node, base_path_specs)

    if not base_path_specs:
      raise errors.ScannerError('No supported file system found in source.')

    return base_path_specs


class WindowsVolumeScanner(VolumeScanner):
  """Windows volume scanner."""

  _WINDOWS_DIRECTORIES = frozenset([
      'C:\\Windows',
      'C:\\WINNT',
      'C:\\WTSRV',
      'C:\\WINNT35',
  ])

  def __init__(self, mediator=None):
    """Initializes a Windows volume scanner.

    Args:
      mediator (VolumeScannerMediator): a volume scanner mediator.
    """
    super(WindowsVolumeScanner, self).__init__(mediator=mediator)
    self._file_system = None
    self._path_resolver = None
    self._windows_directory = None

  def _ScanFileSystem(self, file_system_scan_node, base_path_specs):
    """Scans a file system scan node for file systems.

    This method checks if the file system contains a known Windows directory.

    Args:
      file_system_scan_node (SourceScanNode): file system scan node.
      base_path_specs (list[PathSpec]): file system base path specifications.

    Raises:
      ScannerError: if the scan node is invalid.
    """
    if not file_system_scan_node or not file_system_scan_node.path_spec:
      raise errors.ScannerError('Invalid or missing file system scan node.')

    file_system = resolver.Resolver.OpenFileSystem(
        file_system_scan_node.path_spec)
    if not file_system:
      return

    try:
      path_resolver = windows_path_resolver.WindowsPathResolver(
          file_system, file_system_scan_node.path_spec.parent)

      if self._ScanFileSystemForWindowsDirectory(path_resolver):
        base_path_specs.append(file_system_scan_node.path_spec)

    finally:
      file_system.Close()

  def _ScanFileSystemForWindowsDirectory(self, path_resolver):
    """Scans a file system for a known Windows directory.

    Args:
      path_resolver (WindowsPathResolver): Windows path resolver.

    Returns:
      bool: True if a known Windows directory was found.
    """
    result = False
    for windows_path in self._WINDOWS_DIRECTORIES:
      windows_path_spec = path_resolver.ResolvePath(windows_path)

      result = windows_path_spec is not None
      if result:
        self._windows_directory = windows_path
        break

    return result

  def OpenFile(self, windows_path):
    """Opens the file specificed by the Windows path.

    Args:
      windows_path (str): Windows path to the file.

    Returns:
      FileIO: file-like object or None if the file does not exist.
    """
    path_spec = self._path_resolver.ResolvePath(windows_path)
    if path_spec is None:
      return

    return self._file_system.GetFileObjectByPathSpec(path_spec)

  def ScanForWindowsVolume(self, source_path):
    """Scans for a Windows volume.

    Args:
      source_path (str): source path.

    Returns:
      bool: True if a Windows volume was found.

    Raises:
      ScannerError: if the source path does not exists, or if the source path
          is not a file or directory, or if the format of or within the source
          file is not supported.
    """
    windows_path_specs = self.GetBasePathSpecs(source_path)
    if (not windows_path_specs or
        self._source_type == definitions.SOURCE_TYPE_FILE):
      return False

    file_system_path_spec = windows_path_specs[0]
    self._file_system = resolver.Resolver.OpenFileSystem(file_system_path_spec)

    if file_system_path_spec.type_indicator == definitions.TYPE_INDICATOR_OS:
      mount_point = file_system_path_spec
    else:
      mount_point = file_system_path_spec.parent

    self._path_resolver = windows_path_resolver.WindowsPathResolver(
        self._file_system, mount_point)

    # The source is a directory or single volume storage media image.
    if not self._windows_directory:
      self._ScanFileSystemForWindowsDirectory(self._path_resolver)

    if not self._windows_directory:
      return False

    self._path_resolver.SetEnvironmentVariable(
        'SystemRoot', self._windows_directory)
    self._path_resolver.SetEnvironmentVariable(
        'WinDir', self._windows_directory)

    return True
