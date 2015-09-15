#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the BDE path specification implementation."""

import unittest

from dfvfs.path import bde_path_spec

from tests.path import test_lib


class BdePathSpecTest(test_lib.PathSpecTestCase):
  """Tests for the BDE path specification implementation."""

  def testInitialize(self):
    """Tests the path specification initialization."""
    path_spec = bde_path_spec.BdePathSpec(parent=self._path_spec)

    self.assertNotEqual(path_spec, None)

    with self.assertRaises(ValueError):
      _ = bde_path_spec.BdePathSpec(parent=None)

    with self.assertRaises(ValueError):
      _ = bde_path_spec.BdePathSpec(parent=self._path_spec, bogus=u'BOGUS')

  def testComparable(self):
    """Tests the path specification comparable property."""
    path_spec = bde_path_spec.BdePathSpec(parent=self._path_spec)

    self.assertNotEqual(path_spec, None)

    expected_comparable = u'\n'.join([
        u'type: TEST',
        u'type: BDE',
        u''])

    self.assertEqual(path_spec.comparable, expected_comparable)


if __name__ == '__main__':
  unittest.main()