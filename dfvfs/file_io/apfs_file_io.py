# -*- coding: utf-8 -*-
"""The Apple File System (APFS) file-like object implementation."""

from __future__ import unicode_literals

import os

from dfvfs.file_io import file_io
from dfvfs.lib import errors
from dfvfs.resolver import resolver


class APFSFile(file_io.FileIO):
  """File-like object using pyfsapfs.file_entry"""

  def __init__(self, resolver_context):
    """Initializes a file-like object.

    Args:
      resolver_context (Context): resolver context.
    """
    super(APFSFile, self).__init__(resolver_context)
    self._file_system = None
    self._fsapfs_extended_attribute = None
    self._fsapfs_file_entry = None

  def _Close(self):
    """Closes the file-like object."""
    self._fsapfs_extended_attribute = None
    self._fsapfs_file_entry = None

    self._file_system.Close()
    self._file_system = None

  def _Open(self, path_spec=None, mode='rb'):
    """Opens the file-like object defined by path specification.

    Args:
      path_spec (PathSpec): path specification.
      mode (Optional[str]): file access mode.

    Raises:
      AccessError: if the access to open the file was denied.
      IOError: if the file-like object could not be opened.
      NotSupported: if a data stream, like the resource or named fork, is
          requested to be opened.
      OSError: if the file-like object could not be opened.
      PathSpecError: if the path specification is incorrect.
      ValueError: if the path specification is invalid.
    """
    if not path_spec:
      raise ValueError('Missing path specification.')

    data_stream = getattr(path_spec, 'extended_attribute', None)

    self._file_system = resolver.Resolver.OpenFileSystem(
        path_spec, resolver_context=self._resolver_context)

    file_entry = self._file_system.GetFileEntryByPathSpec(path_spec)
    if not file_entry:
      raise IOError('Unable to open file entry.')

    fsapfs_extended_attribute = None
    fsapfs_file_entry = file_entry.GetAPFSFileEntry()
    if not fsapfs_file_entry:
      raise IOError('Unable to open APFS file entry.')

    if data_stream:
      fsapfs_extended_attribute = fsapfs_file_entry.get_extended_attribute_by_name(
          data_stream)
      if not fsapfs_extended_attribute:
        raise IOError('Unable to open extended attribute: {0:s}.'.format(
            data_stream))

    self._fsapfs_extended_attribute = fsapfs_extended_attribute
    self._fsapfs_file_entry = fsapfs_file_entry

  # Note: that the following functions do not follow the style guide
  # because they are part of the file-like object interface.
  # pylint: disable=invalid-name

  def read(self, size=None):
    """Reads a byte string from the file-like object at the current offset.

    The function will read a byte string of the specified size or
    all of the remaining data if no size was specified.

    Args:
      size (Optional[int]): number of bytes to read, where None is all
          remaining data.

    Returns:
      bytes: data read.

    Raises:
      IOError: if the read failed.
      OSError: if the read failed.
    """
    if not self._is_open:
      raise IOError('Not opened.')

    if self._fsapfs_extended_attribute:
      return self._fsapfs_extended_attribute.read(size=size)
    return self._fsapfs_file_entry.read(size=size)

  def seek(self, offset, whence=os.SEEK_SET):
    """Seeks to an offset within the file-like object.

    Args:
      offset (int): offset to seek to.
      whence (Optional(int)): value that indicates whether offset is an absolute
          or relative position within the file.

    Raises:
      IOError: if the seek failed.
      OSError: if the seek failed.
    """
    if not self._is_open:
      raise IOError('Not opened.')

    if self._fsapfs_extended_attribute:
      self._fsapfs_extended_attribute.seek(offset, whence)
    else:
      self._fsapfs_file_entry.seek(offset, whence)

  def get_offset(self):
    """Retrieves the current offset into the file-like object.

    Returns:
      int: current offset into the file-like object.

    Raises:
      IOError: if the file-like object has not been opened.
      OSError: if the file-like object has not been opened.
    """
    if not self._is_open:
      raise IOError('Not opened.')

    if self._fsapfs_extended_attribute:
      return self._fsapfs_extended_attribute.get_offset()
    return self._fsapfs_file_entry.get_offset()

  def get_size(self):
    """Retrieves the size of the file-like object.

    Returns:
      int: size of the file-like object data.

    Raises:
      IOError: if the file-like object has not been opened.
      OSError: if the file-like object has not been opened.
    """
    if not self._is_open:
      raise IOError('Not opened.')

    if self._fsapfs_extended_attribute:
      return self._fsapfs_extended_attribute.get_size()
    return self._fsapfs_file_entry.get_size()
