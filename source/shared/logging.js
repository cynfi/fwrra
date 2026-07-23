// ============================================================
// Shared logging vocabulary
// ============================================================
// RFC 5424 syslog severity levels. Universal across vendors — ASA, FortiOS,
// and PAN-OS all express log severity/level using this same 0-7 scale (or a
// named subset of it), even though the config syntax to set it differs per
// vendor. Vendor resolve.js modules should classify their own log-directive
// grammar into { flagged, severity, label, detail } and use this table for
// the human-readable level name; don't duplicate the level names per vendor.
const SYSLOG_LEVEL_NAMES = {
  0: 'Emergency', 1: 'Alert', 2: 'Critical', 3: 'Error',
  4: 'Warning', 5: 'Notification', 6: 'Informational', 7: 'Debugging',
};
