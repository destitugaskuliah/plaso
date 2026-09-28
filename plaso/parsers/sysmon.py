"""Parser for Sysmon XML event log files."""

import gzip
import xml.etree.ElementTree as ET

from dfdatetime import time_elements as dfdatetime_time_elements

from plaso.containers import events
from plaso.lib import errors
from plaso.parsers import interface
from plaso.parsers import manager


class SysmonXMLEventData(events.EventData):
  """Sysmon XML event data."""

  DATA_TYPE = 'sysmon:xml:event'

  def __init__(self):
    """Initializes event data."""
    super(SysmonXMLEventData, self).__init__(
        data_type=self.DATA_TYPE)

    self.recorded_time = None
    self.event_id = None
    self.event_record_id = None
    self.provider_name = None
    self.provider_guid = None
    self.channel = None
    self.computer_name = None
    self.security_user_id = None
    self.event_type = None
    self.username = None
    self.hostname = None
    self.process_id = None
    self.process_guid = None
    self.image = None
    self.command_line = None
    self.parent_image = None
    self.parent_command_line = None
    self.parent_process_guid = None
    self.target_image = None
    self.target_object = None
    self.target_filename = None
    self.destination_ip = None
    self.destination_port = None
    self.hashes = None
    self.utc_time = None

    self.source_image = None
    self.source_process_id = None
    self.source_process_guid = None
    self.source_thread_id = None
    self.target_process_guid = None
    self.target_process_id = None
    self.target_user = None
    self.source_user = None
    self.granted_access = None
    self.call_trace = None
    self.details = None
    self.rule_name = None
    self.event_data = None


class SysmonXMLParser(interface.FileObjectParser):
  """Parses Sysmon XML event log files."""

  DATA_FORMAT = 'Sysmon XML log file'
  NAME = 'sysmon_xml'

  _NAMESPACE = (
      'http://schemas.microsoft.com/win/2004/08/events/event')
  _ENCODING = 'cp1252'

  @classmethod
  def _ParseInteger(cls, value):
    """Parses a decimal or hexadecimal integer value."""
    if not value:
      return None
    try:
      return int(value, 0)
    except ValueError:
      try:
        return int(value, 10)
      except ValueError:
        return None

  @classmethod
  def _GetText(cls, element):
    """Returns normalized text from an XML element."""
    if element is None or element.text is None:
      return None
    value = element.text.strip()
    return value or None

  @classmethod
  def _GetSystemValue(cls, system_element, name):
    """Returns a value from a System child element."""
    element = system_element.find(
        f'{{{cls._NAMESPACE}}}{name}')
    return cls._GetText(element)

  @classmethod
  def _CreateTimestamp(cls, system_element):
    """Creates a dfDateTime timestamp from TimeCreated."""
    element = system_element.find(
        f'{{{cls._NAMESPACE}}}TimeCreated')
    if element is None:
      return None

    system_time = element.get('SystemTime')
    if not system_time:
      return None

    timestamp = (
        dfdatetime_time_elements.TimeElementsInNanoseconds())
    timestamp.CopyFromStringISO8601(system_time)
    return timestamp

  @classmethod
  def _BuildEventData(cls, event_element):
    """Builds a Sysmon event data object."""
    event_data = SysmonXMLEventData()

    system_element = event_element.find(
        f'{{{cls._NAMESPACE}}}System')
    if system_element is None:
      return None

    event_data.event_id = cls._ParseInteger(
        cls._GetSystemValue(system_element, 'EventID'))

    event_data.event_record_id = cls._ParseInteger(
        cls._GetSystemValue(system_element, 'EventRecordID'))

    event_data.channel = cls._GetSystemValue(
        system_element, 'Channel')

    event_data.computer_name = cls._GetSystemValue(
        system_element, 'Computer')

    event_data.hostname = event_data.computer_name

    provider_element = system_element.find(
        f'{{{cls._NAMESPACE}}}Provider')
    if provider_element is not None:
      event_data.provider_name = provider_element.get('Name')
      event_data.provider_guid = provider_element.get('Guid')

    security_element = system_element.find(
        f'{{{cls._NAMESPACE}}}Security')
    if security_element is not None:
      event_data.security_user_id = (
          security_element.get('UserID'))

    event_data.recorded_time = cls._CreateTimestamp(
        system_element)

    event_data_element = event_element.find(
        f'{{{cls._NAMESPACE}}}EventData')
    if event_data_element is None:
      return event_data

    event_values = {}

    for data_element in event_data_element.findall(
        f'{{{cls._NAMESPACE}}}Data'):
      name = data_element.get('Name')
      value = cls._GetText(data_element)

      if name:
        event_values[name] = value

    event_data.event_type = event_values.get('EventType')
    event_data.username = event_values.get('User')

    event_data.process_id = cls._ParseInteger(
        event_values.get('ProcessId'))

    event_data.destination_port = cls._ParseInteger(
        event_values.get('DestinationPort'))

    event_data.process_guid = event_values.get('ProcessGuid')
    event_data.image = event_values.get('Image')
    event_data.command_line = event_values.get('CommandLine')
    event_data.parent_image = event_values.get('ParentImage')
    event_data.parent_command_line = event_values.get(
        'ParentCommandLine')
    event_data.parent_process_guid = event_values.get(
        'ParentProcessGuid')
    event_data.target_image = event_values.get('TargetImage')
    event_data.target_object = event_values.get('TargetObject')
    event_data.target_filename = event_values.get(
        'TargetFilename')
    event_data.destination_ip = event_values.get(
        'DestinationIp')
    event_data.hashes = event_values.get('Hashes')
    event_data.utc_time = event_values.get('UtcTime')

    event_data.source_image = event_values.get('SourceImage')
    event_data.source_process_id = cls._ParseInteger(
        event_values.get('SourceProcessId'))
    event_data.source_process_guid = event_values.get(
        'SourceProcessGUID')
    event_data.source_thread_id = cls._ParseInteger(
        event_values.get('SourceThreadId'))
    event_data.target_process_guid = event_values.get(
        'TargetProcessGUID')
    event_data.target_process_id = cls._ParseInteger(
        event_values.get('TargetProcessId'))
    event_data.target_user = event_values.get('TargetUser')
    event_data.source_user = event_values.get('SourceUser')
    event_data.granted_access = event_values.get('GrantedAccess')
    event_data.call_trace = event_values.get('CallTrace')
    event_data.details = event_values.get('Details')
    event_data.rule_name = event_values.get('RuleName')

    return event_data

  def _ReadXML(self, file_object):
    """Reads XML from plain or gzip-compressed input."""
    file_object.seek(0)
    file_content = file_object.read()

    if file_content[:2] == b'\x1f\x8b':
      try:
        file_content = gzip.decompress(file_content)
      except OSError as exception:
        raise errors.WrongParser(
            f'Unable to decompress Sysmon XML file: {exception!s}')

    try:
      xml_text = file_content.decode('utf-8')
    except UnicodeDecodeError:
      try:
        xml_text = file_content.decode(self._ENCODING)
      except UnicodeDecodeError as exception:
        raise errors.WrongParser(
            f'Unable to decode Sysmon XML file: {exception!s}')

    try:
      return ET.fromstring(xml_text)
    except ET.ParseError as exception:
      raise errors.WrongParser(
          f'Unable to parse Sysmon XML file: {exception!s}')

  def ParseFileObject(self, parser_mediator, file_object):
    """Parses a Sysmon XML file-like object."""
    root = self._ReadXML(file_object)

    event_elements = root.findall(
        f'{{{self._NAMESPACE}}}Event')

    if not event_elements:
      raise errors.WrongParser(
          'No Windows Event elements found.')

    sysmon_event_count = 0

    for event_element in event_elements:
      event_data = self._BuildEventData(event_element)

      if event_data is None:
        parser_mediator.ProduceExtractionWarning(
            'Sysmon event is missing the System element.')
        continue

      if event_data.provider_name != 'Microsoft-Windows-Sysmon':
        continue

      sysmon_event_count += 1

      parser_mediator.ProduceEventData(event_data)

      if parser_mediator.abort:
        break

    if not sysmon_event_count:
      raise errors.WrongParser(
          'No Microsoft-Windows-Sysmon events found.')


manager.ParsersManager.RegisterParser(SysmonXMLParser)