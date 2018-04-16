# -*- coding: utf-8 -*-
"""Helpers for command-line scripts."""

from __future__ import print_function
from __future__ import unicode_literals

import getpass
import locale
import logging
import sys

from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.lib import errors
from dfvfs.helpers import volume_scanner


class CLIVolumeScannerMediator(volume_scanner.VolumeScannerMediator):
  """Volume scanner mediator for the command-line."""

  _BINARY_DATA_CREDENTIAL_TYPES = ['key_data']

  _SUPPORTED_CREDENTIAL_TYPES = [
      'key_data', 'password', 'recovery_password', 'startup_key']

  # For context see: http://en.wikipedia.org/wiki/Byte
  _UNITS_1000 = ['B', 'kB', 'MB', 'GB', 'TB', 'EB', 'ZB', 'YB']
  _UNITS_1024 = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'EiB', 'ZiB', 'YiB']

  def __init__(self):
    """Initializes a volume scanner mediator."""
    super(CLIVolumeScannerMediator, self).__init__()
    self._encode_errors = 'strict'
    # TODO: add default output writer.
    self._output_writer = None
    # TODO: set preferred encoding or move encoding to output writer.
    self._preferred_encoding = locale.getpreferredencoding()

  def _EncodeString(self, string):
    """Encodes a string in the preferred encoding.

    Returns:
      bytes: encoded string.
    """
    try:
      # Note that encode() will first convert string into a Unicode string
      # if necessary.
      encoded_string = string.encode(
          self._preferred_encoding, errors=self._encode_errors)
    except UnicodeEncodeError:
      if self._encode_errors == 'strict':
        logging.error(
            'Unable to properly write output due to encoding error. '
            'Switching to error tolerant encoding which can result in '
            'non Basic Latin (C0) characters to be replaced with "?" or '
            '"\\ufffd".')
        self._encode_errors = 'replace'

      encoded_string = string.encode(
          self._preferred_encoding, errors=self._encode_errors)

    return encoded_string

  def _FormatHumanReadableSize(self, size):
    """Represents a number of bytes as a human readable string.

    Args:
      size (int): size in bytes.

    Returns:
      str: human readable string of the size.
    """
    magnitude_1000 = 0
    size_1000 = float(size)
    while size_1000 >= 1000:
      size_1000 /= 1000
      magnitude_1000 += 1

    magnitude_1024 = 0
    size_1024 = float(size)
    while size_1024 >= 1024:
      size_1024 /= 1024
      magnitude_1024 += 1

    size_string_1000 = None
    if magnitude_1000 > 0 and magnitude_1000 <= 7:
      size_string_1000 = '{0:.1f}{1:s}'.format(
          size_1000, self._UNITS_1000[magnitude_1000])

    size_string_1024 = None
    if magnitude_1024 > 0 and magnitude_1024 <= 7:
      size_string_1024 = '{0:.1f}{1:s}'.format(
          size_1024, self._UNITS_1024[magnitude_1024])

    if not size_string_1000 or not size_string_1024:
      return '{0:d} B'.format(size)

    return '{0:s} / {1:s} ({2:d} B)'.format(
        size_string_1024, size_string_1000, size)

  def _ParseVSSStoresString(self, vss_stores):
    """Parses the user specified VSS stores string.

    Args:
      vss_stores (str): VSS stores. A range of stores can be defined
          as: "3..5". Multiple stores can be defined as: "1,3,5" (a list
          of comma separated values). Ranges and lists can also be
          combined as: "1,3..5". The first store is 1. All stores can be
          defined as: "all".

    Returns:
      list[str]: VSS stores.

    Raises:
      ValueError: if the VSS stores option is invalid.
    """
    if not vss_stores:
      return []

    if vss_stores == 'all':
      return ['all']

    store_numbers = []
    for vss_store_range in vss_stores.split(','):
      # Determine if the range is formatted as 1..3 otherwise it indicates
      # a single store number.
      if '..' in vss_store_range:
        first_store, last_store = vss_store_range.split('..')
        try:
          first_store = int(first_store, 10)
          last_store = int(last_store, 10)
        except ValueError:
          raise ValueError('Invalid VSS store range: {0!s}.'.format(
              vss_store_range))

        for store_number in range(first_store, last_store + 1):
          if store_number not in store_numbers:
            store_numbers.append(store_number)
      else:
        if vss_store_range.startswith('vss'):
          vss_store_range = vss_store_range[3:]

        try:
          store_number = int(vss_store_range, 10)
        except ValueError:
          raise ValueError('Invalid VSS store range: {0!s}.'.format(
              vss_store_range))

        if store_number not in store_numbers:
          store_numbers.append(store_number)

    return sorted(store_numbers)

  def PromptUserForEncryptedVolumeCredential(
      self, scan_context, locked_scan_node, credentials):
    """Prompts the user to provide a credential for an encrypted volume.

    Args:
      scan_context (dfvfs.SourceScannerContext): source scanner context.
      locked_scan_node (dfvfs.SourceScanNode): locked scan node.
      credentials (dfvfs.Credentials): credentials supported by the locked
          scan node.

    Returns:
      bool: True if the volume was unlocked.
    """
    # TODO: print volume description.
    if locked_scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_BDE:
      self._output_writer.Write('Found a BitLocker encrypted volume.\n')
    else:
      self._output_writer.Write('Found an encrypted volume.\n')

    credentials_list = list(credentials.CREDENTIALS)
    credentials_list.append('skip')

    self._output_writer.Write('Supported credentials:\n')
    self._output_writer.Write('\n')
    for index, name in enumerate(credentials_list):
      self._output_writer.Write('  {0:d}. {1:s}\n'.format(index, name))
    self._output_writer.Write('\nNote that you can abort with Ctrl^C.\n\n')

    result = False
    while not result:
      self._output_writer.Write('Select a credential to unlock the volume: ')
      # TODO: add an input reader.
      input_line = self._input_reader.Read()
      input_line = input_line.strip()

      if input_line in credentials_list:
        credential_type = input_line
      else:
        try:
          credential_type = int(input_line, 10)
          credential_type = credentials_list[credential_type]
        except (IndexError, ValueError):
          self._output_writer.Write(
              'Unsupported credential: {0:s}\n'.format(input_line))
          continue

      if credential_type == 'skip':
        break

      getpass_string = 'Enter credential data: '
      if sys.platform.startswith('win') and sys.version_info[0] < 3:
        # For Python 2 on Windows getpass (win_getpass) requires an encoded
        # byte string. For Python 3 we need it to be a Unicode string.
        getpass_string = self._EncodeString(getpass_string)

      credential_data = getpass.getpass(getpass_string)
      self._output_writer.Write('\n')

      if credential_type in self._BINARY_DATA_CREDENTIAL_TYPES:
        try:
          credential_data = credential_data.decode('hex')
        except TypeError:
          self._output_writer.Write('Unsupported credential data.\n')
          continue

      try:
        result = self._source_scanner.Unlock(
            scan_context, locked_scan_node.path_spec, credential_type,
            credential_data)

      except IOError as exception:
        logging.debug('Unable to unlock volume with error: {0!s}'.format(
            exception))
        result = False

      if not result:
        self._output_writer.Write('Unable to unlock volume.\n')
        self._output_writer.Write('\n')

    self._output_writer.Write('\n')

    if result:
      self._AddCredentialConfiguration(
          locked_scan_node.path_spec, credential_type, credential_data)

    return result

  def PromptUserForPartitionIdentifiers(
      self, volume_system, volume_identifiers):
    """Prompts the user to provide partition identifiers.

    Args:
      volume_system (dfvfs.TSKVolumeSystem): volume system.
      volume_identifiers (list[str]): allowed volume identifiers.

    Returns:
      str: partition identifier or 'all'.

    Raises:
      SourceScannerError: if the source cannot be processed.
    """
    self._output_writer.Write('The following partitions were found:\n')

    table_view = views.CLITabularTableView(column_names=[
        'Identifier', 'Offset (in bytes)', 'Size (in bytes)'])

    for volume_identifier in sorted(volume_identifiers):
      volume = volume_system.GetVolumeByIdentifier(volume_identifier)
      if not volume:
        raise errors.SourceScannerError(
            'Volume missing for identifier: {0:s}.'.format(volume_identifier))

      volume_extent = volume.extents[0]
      volume_offset = '{0:d} (0x{0:08x})'.format(volume_extent.offset)
      volume_size = self._FormatHumanReadableSize(volume_extent.size)

      table_view.AddRow([volume.identifier, volume_offset, volume_size])

    self._output_writer.Write('\n')
    table_view.Write(self._output_writer)
    self._output_writer.Write('\n')

    while True:
      self._output_writer.Write(
          'Please specify the identifier of the partition that should be '
          'processed.\nAll partitions can be defined as: "all". Note that you '
          'can abort with Ctrl^C.\n')

      selected_volume_identifier = self._input_reader.Read()
      selected_volume_identifier = selected_volume_identifier.strip()

      if not selected_volume_identifier.startswith('p'):
        try:
          partition_number = int(selected_volume_identifier, 10)
          selected_volume_identifier = 'p{0:d}'.format(partition_number)
        except ValueError:
          pass

      if (selected_volume_identifier == 'all' or
          selected_volume_identifier in volume_identifiers):
        break

      self._output_writer.Write(
          '\n'
          'Unsupported partition identifier, please try again or abort '
          'with Ctrl^C.\n'
          '\n')

    self._output_writer.Write('\n')
    return selected_volume_identifier

  def PromptUserForVSSCurrentVolume(self):
    """Prompts the user if the current volume with VSS should be processed.

    Returns:
      bool: True if the current volume with VSS should be processed.
    """
    while True:
      self._output_writer.Write(
          'Volume Shadow Snapshots (VSS) were selected also process current\n'
          'volume? [yes, no]\n')

      process_current_volume = self._input_reader.Read()
      process_current_volume = process_current_volume.strip()
      process_current_volume = process_current_volume.lower()

      if (not process_current_volume or
          process_current_volume in ('no', 'yes')):
        break

      self._output_writer.Write(
          '\n'
          'Unsupported option, please try again or abort with Ctrl^C.\n'
          '\n')

    self._output_writer.Write('\n')
    return not process_current_volume or process_current_volume == 'yes'

  def PromptUserForVSSStoreIdentifiers(
      self, volume_system, volume_identifiers, vss_stores=None):
    """Prompts the user to provide the VSS store identifiers.

    This method first checks for the preferred VSS stores and falls back
    to prompt the user if no usable preferences were specified.

    Args:
      volume_system (dfvfs.VShadowVolumeSystem): volume system.
      volume_identifiers (list[str]): allowed volume identifiers.
      vss_stores (Optional[list[str]]): preferred VSS store identifiers.

    Returns:
      list[str]: selected VSS store identifiers.

    Raises:
      SourceScannerError: if the source cannot be processed.
    """
    normalized_volume_identifiers = self._GetNormalizedVShadowVolumeIdentifiers(
        volume_system, volume_identifiers)

    # TODO: refactor this to _GetVSSStoreIdentifiers.
    if vss_stores:
      if vss_stores == ['all']:
        # We need to set the stores to cover all vss stores.
        vss_stores = range(1, volume_system.number_of_volumes + 1)

      if not set(vss_stores).difference(normalized_volume_identifiers):
        return vss_stores

    print_header = True
    while True:
      if print_header:
        self._output_writer.Write(
            'The following Volume Shadow Snapshots (VSS) were found:\n')

        table_view = views.CLITabularTableView(column_names=[
            'Identifier', 'Creation Time'])

        for volume_identifier in volume_identifiers:
          volume = volume_system.GetVolumeByIdentifier(volume_identifier)
          if not volume:
            raise errors.SourceScannerError(
                'Volume missing for identifier: {0:s}.'.format(
                    volume_identifier))

          vss_creation_time = volume.GetAttribute('creation_time')
          filetime = dfdatetime_filetime.Filetime(
              timestamp=vss_creation_time.value)
          vss_creation_time = filetime.GetPlasoTimestamp()
          vss_creation_time = timelib.Timestamp.CopyToIsoFormat(
              vss_creation_time)

          if volume.HasExternalData():
            vss_creation_time = (
                '{0:s}\tWARNING: data stored outside volume').format(
                    vss_creation_time)

          table_view.AddRow([volume.identifier, vss_creation_time])

        self._output_writer.Write('\n')
        table_view.Write(self._output_writer)
        self._output_writer.Write('\n')

        print_header = False

      self._output_writer.Write(
          'Please specify the identifier(s) of the VSS that should be '
          'processed:\nNote that a range of stores can be defined as: 3..5. '
          'Multiple stores can\nbe defined as: 1,3,5 (a list of comma '
          'separated values). Ranges and lists can\nalso be combined '
          'as: 1,3..5. The first store is 1. All stores can be defined\n'
          'as "all". If no stores are specified none will be processed. You\n'
          'can abort with Ctrl^C.\n')

      selected_vss_stores = self._input_reader.Read()

      selected_vss_stores = selected_vss_stores.strip()
      if not selected_vss_stores:
        return []

      try:
        selected_vss_stores = self._ParseVSSStoresString(selected_vss_stores)
      except ValueError:
        selected_vss_stores = []

      if selected_vss_stores == ['all']:
        # We need to set the stores to cover all vss stores.
        selected_vss_stores = range(1, volume_system.number_of_volumes + 1)

      if not set(selected_vss_stores).difference(normalized_volume_identifiers):
        break

      self._output_writer.Write(
          '\n'
          'Unsupported VSS identifier(s), please try again or abort with '
          'Ctrl^C.\n'
          '\n')

    self._output_writer.Write('\n')
    return selected_vss_stores

  def UnlockEncryptedVolume(
      self, source_scanner_object, scan_context, locked_scan_node, credentials):
    """Unlocks an encrypted volume.

    This method can be used to prompt the user to provide encrypted volume
    credentials.

    Args:
      source_scanner_object (dfvfs.SourceScanner): source scanner.
      scan_context (dfvfs.SourceScannerContext): source scanner context.
      locked_scan_node (dfvfs.SourceScanNode): locked scan node.
      credentials (dfvfs.Credentials): credentials supported by the locked
          scan node.

    Returns:
      bool: True if the volume was unlocked.
    """
    # TODO: print volume description.
    if locked_scan_node.type_indicator == dfvfs_definitions.TYPE_INDICATOR_BDE:
      print('Found a BitLocker encrypted volume.')
    else:
      print('Found an encrypted volume.')

    credentials_list = list(credentials.CREDENTIALS)
    credentials_list.append('skip')

    print('Supported credentials:')
    print('')
    for index, name in enumerate(credentials_list):
      print('  {0:d}. {1:s}'.format(index, name))
    print('')
    print('Note that you can abort with Ctrl^C.')
    print('')

    result = False
    while not result:
      print('Select a credential to unlock the volume: ', end='')
      # TODO: add an input reader.
      input_line = sys.stdin.readline()
      input_line = input_line.strip()

      if input_line in credentials_list:
        credential_type = input_line
      else:
        try:
          credential_type = int(input_line, 10)
          credential_type = credentials_list[credential_type]
        except (IndexError, ValueError):
          print('Unsupported credential: {0:s}'.format(input_line))
          continue

      if credential_type == 'skip':
        break

      getpass_string = 'Enter credential data: '
      if sys.platform.startswith('win') and sys.version_info[0] < 3:
        # For Python 2 on Windows getpass (win_getpass) requires an encoded
        # byte string. For Python 3 we need it to be a Unicode string.
        getpass_string = self._EncodeString(getpass_string)

      credential_data = getpass.getpass(getpass_string)
      print('')

      if credential_type == 'key':
        try:
          credential_data = credential_data.decode('hex')
        except TypeError:
          print('Unsupported credential data.')
          continue

      result = source_scanner_object.Unlock(
          scan_context, locked_scan_node.path_spec, credential_type,
          credential_data)

      if not result:
        print('Unable to unlock volume.')
        print('')

    return result

  def WarnUserForNoPartitionAtOffset(self, partition_offset):
    """Warns the user that not partitions were found.

    Args:
      partition_offset (int): offset where the partition is supposed to start.
    """
    self._output_writer.Write(
        '[WARNING] No such partition with offset: {0:d} (0x{0:08x}).\n'.format(
            partition_offset))

  def WarnUserForNoPartitionsFound(self):
    """Warns the user that not partitions were found."""
    self._output_writer.Write('[WARNING] No partitions found.\n')

  def WarnUserForUnableUnlockEncryptedVolume(self):
    """Warns the user that an encrypted volume could not be unlocked."""
    self._output_writer.Write(
        '[WARNING] Unable to unlock encrypted volume using the provided '
        'credentials.\n\n')
