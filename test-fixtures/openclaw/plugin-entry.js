export function definePluginEntry(entry) {
  return {
    ...entry,
    configSchema: entry.configSchema ?? {},
  };
}
