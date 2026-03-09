"""Test fixtures - generated protobuf samples."""

import os
from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2, telemetry_pb2

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_text_message_fixture():
    """Generate a ServiceEnvelope with TEXT_MESSAGE_APP."""
    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.channel_id = "LongFast"
    envelope.gateway_id = "!aabbccdd"
    envelope.packet.id = 12345
    envelope.packet.to = 0xFFFFFFFF
    setattr(envelope.packet, 'from', 0x11223344)  # 'from' is a Python keyword
    envelope.packet.decoded.portnum = portnums_pb2.TEXT_MESSAGE_APP
    envelope.packet.decoded.payload = b"Hello mesh!"
    
    with open(os.path.join(FIXTURES_DIR, "text_message.bin"), "wb") as f:
        f.write(envelope.SerializeToString())
    
    print(f"Generated text_message.bin ({len(envelope.SerializeToString())} bytes)")


def generate_position_fixture():
    """Generate a ServiceEnvelope with POSITION_APP."""
    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.channel_id = "LongFast"
    envelope.gateway_id = "!aabbccdd"
    envelope.packet.id = 12346
    envelope.packet.to = 0xFFFFFFFF
    setattr(envelope.packet, 'from', 0x11223344)  # 'from' is a Python keyword
    envelope.packet.decoded.portnum = portnums_pb2.POSITION_APP
    
    # Create a position message
    position = mesh_pb2.Position()
    position.latitude_i = int(-23.5 * 1e7)
    position.longitude_i = int(-46.6 * 1e7)
    position.altitude = 760
    envelope.packet.decoded.payload = position.SerializeToString()
    
    with open(os.path.join(FIXTURES_DIR, "position.bin"), "wb") as f:
        f.write(envelope.SerializeToString())
    
    print(f"Generated position.bin ({len(envelope.SerializeToString())} bytes)")


def generate_telemetry_fixture():
    """Generate a ServiceEnvelope with TELEMETRY_APP."""
    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.channel_id = "LongFast"
    envelope.gateway_id = "!aabbccdd"
    envelope.packet.id = 12347
    envelope.packet.to = 0xFFFFFFFF
    setattr(envelope.packet, 'from', 0x11223344)  # 'from' is a Python keyword
    envelope.packet.decoded.portnum = portnums_pb2.TELEMETRY_APP
    
    # Create a telemetry message
    telemetry = telemetry_pb2.Telemetry()
    telemetry.device_metrics.battery_level = 85
    telemetry.device_metrics.voltage = 3.7
    envelope.packet.decoded.payload = telemetry.SerializeToString()
    
    with open(os.path.join(FIXTURES_DIR, "telemetry.bin"), "wb") as f:
        f.write(envelope.SerializeToString())
    
    print(f"Generated telemetry.bin ({len(envelope.SerializeToString())} bytes)")


def generate_nodeinfo_fixture():
    """Generate a ServiceEnvelope with NODEINFO_APP."""
    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.channel_id = "LongFast"
    envelope.gateway_id = "!aabbccdd"
    envelope.packet.id = 12348
    envelope.packet.to = 0xFFFFFFFF
    setattr(envelope.packet, 'from', 0x11223344)  # 'from' is a Python keyword
    envelope.packet.decoded.portnum = portnums_pb2.NODEINFO_APP
    
    # Create a user (nodeinfo) message
    user = mesh_pb2.User()
    user.id = "!11223344"
    user.long_name = "Test Node"
    user.short_name = "TEST"
    envelope.packet.decoded.payload = user.SerializeToString()
    
    with open(os.path.join(FIXTURES_DIR, "nodeinfo.bin"), "wb") as f:
        f.write(envelope.SerializeToString())
    
    print(f"Generated nodeinfo.bin ({len(envelope.SerializeToString())} bytes)")


def generate_all_fixtures():
    """Generate all test fixtures."""
    generate_text_message_fixture()
    generate_position_fixture()
    generate_telemetry_fixture()
    generate_nodeinfo_fixture()
    print("All fixtures generated!")


if __name__ == "__main__":
    generate_all_fixtures()
