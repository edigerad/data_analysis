# json_logs.zeek — Zeek policy script to output JSON logs
#
# Usage:
#   zeek -r capture.pcap scripts/json_logs.zeek
#
# This is an alternative to passing LogAscii::use_json=T on the command line.
# Useful when you want to version-control the output configuration.

redef LogAscii::use_json = T;

# Set a consistent JSON timestamp format (ISO 8601) instead of epoch floats.
# Makes pandas.to_datetime() work without specifying unit="s".
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
