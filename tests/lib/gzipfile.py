#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for gzip compressed stream file."""

# Note: do not rename file to gzip.py this can cause the exception:
# AttributeError: 'module' object has no attribute 'GzipFile'
# when using pip.

from __future__ import unicode_literals

import os
import unittest

from dfvfs.file_io import file_object_io
from dfvfs.lib import gzipfile

from tests import test_lib as shared_test_lib


class GzipDecompressorStateTest(shared_test_lib.BaseTestCase):
  """Tests the deflate decompressor wrapper for reading a gzip member."""

  # TODO: add tests for _GetUnusedData

  def testRead(self):
    """Tests the Read function."""

    # TODO: implement.


class GzipMemberTest(shared_test_lib.BaseTestCase):
  """Tests the gzip member."""

  # TODO: add tests for _LoadDataIntoCache

  def testReadMemberFooter(self):
    """Tests the _ReadMemberFooter function."""
    test_path = self._GetTestFilePath(['syslog.gz'])
    self._SkipIfPathNotExists(test_path)

    with open(test_path, 'rb') as file_object:
      file_io_object = file_object_io.FileObjectIO(None, file_object=file_object)
      file_io_object.open()

      try:
        gzip_member = gzipfile.GzipMember(file_io_object, 0, 0)

        file_io_object.seek(-8, os.SEEK_END)
        gzip_member._ReadMemberFooter(file_io_object)
      finally:
        file_io_object.close()

  def testReadMemberHeader(self):
    """Tests the _ReadMemberHeader function."""
    test_path = self._GetTestFilePath(['syslog.gz'])
    self._SkipIfPathNotExists(test_path)

    with open(test_path, 'rb') as file_object:
      file_io_object = file_object_io.FileObjectIO(None, file_object=file_object)
      file_io_object.open()

      try:
        gzip_member = gzipfile.GzipMember(file_io_object, 0, 0)

        file_io_object.seek(0, os.SEEK_SET)
        gzip_member._ReadMemberHeader(file_io_object)
      finally:
        file_io_object.close()

  def testResetDecompressorState(self):
    """Tests the _ResetDecompressorState function."""
    test_path = self._GetTestFilePath(['syslog.gz'])
    self._SkipIfPathNotExists(test_path)

    with open(test_path, 'rb') as file_object:
      file_io_object = file_object_io.FileObjectIO(None, file_object=file_object)
      file_io_object.open()

      try:
        gzip_member = gzipfile.GzipMember(file_io_object, 0, 0)

        gzip_member._ResetDecompressorState()
      finally:
        file_io_object.close()

  def testFlushCache(self):
    """Tests the FlushCache function."""
    test_path = self._GetTestFilePath(['syslog.gz'])
    self._SkipIfPathNotExists(test_path)

    with open(test_path, 'rb') as file_object:
      file_io_object = file_object_io.FileObjectIO(None, file_object=file_object)
      file_io_object.open()

      try:
        gzip_member = gzipfile.GzipMember(file_io_object, 0, 0)

        gzip_member.FlushCache()
      finally:
        file_io_object.close()

  def testGetCacheSize(self):
    """Tests the GetCacheSize function."""
    test_path = self._GetTestFilePath(['syslog.gz'])
    self._SkipIfPathNotExists(test_path)

    with open(test_path, 'rb') as file_object:
      file_io_object = file_object_io.FileObjectIO(None, file_object=file_object)
      file_io_object.open()

      try:
        gzip_member = gzipfile.GzipMember(file_io_object, 0, 0)

        cache_size = gzip_member.GetCacheSize()
      finally:
        file_io_object.close()

    self.assertEqual(cache_size, 0)

  def testIsCacheFull(self):
    """Tests the IsCacheFull function."""
    test_path = self._GetTestFilePath(['syslog.gz'])
    self._SkipIfPathNotExists(test_path)

    with open(test_path, 'rb') as file_object:
      file_io_object = file_object_io.FileObjectIO(None, file_object=file_object)
      file_io_object.open()

      try:
        gzip_member = gzipfile.GzipMember(file_io_object, 0, 0)

        is_cache_full = gzip_member.IsCacheFull()
      finally:
        file_io_object.close()

    self.assertFalse(is_cache_full)

  # TODO: add tests for ReadAtOffset


if __name__ == '__main__':
  unittest.main()
