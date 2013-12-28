#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2013 The PyVFS Project Authors.
# Please see the AUTHORS file for details on individual authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for the file-like object implementation using TSK partition."""

import os
import unittest

from pyvfs.lib import errors
from pyvfs.file_io import tsk_partition_file_io
from pyvfs.path import os_path_spec
from pyvfs.path import tsk_partition_path_spec


class TSKPartitionFileTest(unittest.TestCase):
  """The unit test for the SleuthKit (TSK) partition file-like object."""

  def setUp(self):
    """Sets up the needed objects used throughout the test."""
    test_file = os.path.join('test_data', 'tsk_volume_system.raw')
    self._os_path_spec = os_path_spec.OSPathSpec(location=test_file)

  # mmls test_data/tsk_volume_system.raw
  # DOS Partition Table
  # Offset Sector: 0
  # Units are in 512-byte sectors
  #
  #      Slot    Start        End          Length       Description
  # 00:  Meta    0000000000   0000000000   0000000001   Primary Table (#0)
  # 01:  -----   0000000000   0000000000   0000000001   Unallocated
  # 02:  00:00   0000000001   0000000350   0000000350   Linux (0x83)
  # 03:  Meta    0000000351   0000002879   0000002529   DOS Extended (0x05)
  # 04:  Meta    0000000351   0000000351   0000000001   Extended Table (#1)
  # 05:  -----   0000000351   0000000351   0000000001   Unallocated
  # 06:  01:00   0000000352   0000002879   0000002528   Linux (0x83)

  def testOpenClose(self):
    """Test the open and close functionality."""
    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        part_index=2, parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    file_object.open(path_spec)
    self.assertEquals(file_object.get_size(), 350 * 512)
    file_object.close()

    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        part_index=13, parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    with self.assertRaises(errors.PathSpecError):
      file_object.open(path_spec)

    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        location=u'/p2', parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    file_object.open(path_spec)
    self.assertEquals(file_object.get_size(), 2528 * 512)
    file_object.close()

    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        location=u'/p0', parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    with self.assertRaises(errors.PathSpecError):
      file_object.open(path_spec)

    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        location=u'/p3', parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    with self.assertRaises(errors.PathSpecError):
      file_object.open(path_spec)

    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        start_offset=(352 * 512), parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    file_object.open(path_spec)
    self.assertEquals(file_object.get_size(), 2528 * 512)
    file_object.close()

    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        start_offset=(350 * 512), parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()

    with self.assertRaises(errors.PathSpecError):
      file_object.open(path_spec)

  def testSeek(self):
    """Test the seek functionality."""
    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        part_index=6, parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()
    partition_offset = 352 * 512

    file_object.open(path_spec)
    self.assertEquals(file_object.get_size(), 2528 * 512)

    file_object.seek(0x7420)
    self.assertEquals(file_object.get_offset(), 0x33420 - partition_offset)
    self.assertEquals(
        file_object.read(16), 'lost+found\x00\x00\x00\x00\x00\x00')
    self.assertEquals(file_object.get_offset(), 0x33430 - partition_offset)

    file_object.seek(-1251324, os.SEEK_END)
    self.assertEquals(file_object.get_offset(), 0x36804 - partition_offset)
    self.assertEquals(file_object.read(8), '\x03\x00\x00\x00\x04\x00\x00\x00')
    self.assertEquals(file_object.get_offset(), 0x3680c - partition_offset)

    file_object.seek(4, os.SEEK_CUR)
    self.assertEquals(file_object.get_offset(), 0x36810 - partition_offset)
    self.assertEquals(file_object.read(7), '\x06\x00\x00\x00\x00\x00\x00')
    self.assertEquals(file_object.get_offset(), 0x36817 - partition_offset)

    # Conforming to the POSIX seek the offset can exceed the file size
    # but reading will result in no data being returned.
    expected_offset = (2528 * 512) + 100
    file_object.seek(expected_offset, os.SEEK_SET)
    self.assertEquals(file_object.get_offset(), expected_offset)
    self.assertEquals(file_object.read(20), '')

    with self.assertRaises(IOError):
      file_object.seek(-10, os.SEEK_SET)

    # On error the offset should not change.
    self.assertEquals(file_object.get_offset(), expected_offset)

    with self.assertRaises(IOError):
      file_object.seek(10, 5)

    # On error the offset should not change.
    self.assertEquals(file_object.get_offset(), expected_offset)

    file_object.close()

  def testRead(self):
    """Test the read functionality."""
    path_spec = tsk_partition_path_spec.TSKPartitionPathSpec(
        part_index=6, parent=self._os_path_spec)
    file_object = tsk_partition_file_io.TSKPartitionFile()
    partition_offset = 352 * 512

    file_object.open(path_spec)
    self.assertEquals(file_object.get_size(), 2528 * 512)

    file_object.seek(0x2e900 - partition_offset)

    expected_data = (
        '\xc0\x41\x00\x00\x00\x30\x00\x00\xc8\x8c\xb9\x52\xc8\x8c\xb9\x52'
        '\xc8\x8c\xb9\x52\x00\x00\x00\x00\x00\x00\x02\x00\x18\x00\x00\x00')

    self.assertEquals(file_object.read(32), expected_data)

    file_object.close()


if __name__ == '__main__':
  unittest.main()