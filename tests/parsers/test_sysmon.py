#!/usr/bin/env python3
"""Tests for the Sysmon XML parser."""

import unittest

from plaso.parsers import sysmon
from tests.parsers import test_lib


class SysmonXMLParserTest(test_lib.ParserTestCase):
  """Tests the Sysmon XML parser."""

  def testParseFile(self):
    """Tests parsing the Sysmon XML test file."""
    parser = sysmon.SysmonXMLParser()

    storage_writer = self._ParseFile(
        ['sysmon.events.xml'], parser)

    number_of_event_data = (
        storage_writer.GetNumberOfAttributeContainers(
            'event_data'))

    self.assertEqual(
        number_of_event_data,
        6801)

    number_of_warnings = (
        storage_writer.GetNumberOfAttributeContainers(
            'extraction_warning'))

    self.assertEqual(
        number_of_warnings,
        0)

    event_data = (
        storage_writer.GetAttributeContainerByIndex(
            'event_data', 0))

    self.CheckEventData(
        event_data,
        {
            'data_type': 'sysmon:xml:event',
            'event_id': 10,
            'event_record_id': 2867,
            'provider_name': 'Microsoft-Windows-Sysmon',
            'computer_name': 'wGwBpYIH',
            'hostname': 'wGwBpYIH',
            'event_type': None,
        })

    self.assertEqual(
        event_data.rule_name,
        '-')

    self.assertEqual(
        event_data.source_image,
        r'C:\Windows\system32\svchost.exe')

    self.assertEqual(
        event_data.target_image,
        r'C:\Windows\system32\csrss.exe')

    self.assertEqual(
        event_data.recorded_time.CopyToDateTimeString(),
        '2026-06-13 12:18:57.018493900')

    event_data = (
        storage_writer.GetAttributeContainerByIndex(
            'event_data', 4))

    self.assertEqual(
        event_data.event_id,
        12)

    self.assertEqual(
        event_data.event_type,
        'CreateKey')

    self.assertEqual(
        event_data.image,
        r'C:\Windows\Explorer.EXE')

    self.assertEqual(
        event_data.target_object,
        r'HKU\S-1-5-21-3292694554-3817943201-570392938-500'
        r'\Software\Microsoft\Windows\CurrentVersion\Explorer'
        r'\SessionInfo\1\ApplicationViewManagement\W32:00000000000E0202')

    event_data = (
        storage_writer.GetAttributeContainerByIndex(
            'event_data', 5))

    self.assertEqual(
        event_data.event_id,
        13)

    self.assertEqual(
        event_data.event_type,
        'SetValue')

    self.assertEqual(
        event_data.details,
        'Binary Data')


if __name__ == '__main__':
  unittest.main()