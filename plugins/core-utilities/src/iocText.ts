export function defangText(input: string): string {
  return input
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/@/g, "[@]")
    .replace(/\./g, "[.]");
}

export function refangText(input: string): string {
  return input
    .replace(/hxxps:\/\//gi, "https://")
    .replace(/hxxp:\/\//gi, "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\(\.\)/g, ".")
    .replace(/\[dot\]/gi, ".")
    .replace(/\[@\]/g, "@")
    .replace(/\(at\)/gi, "@");
}

export function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

export function trimTrailingPunctuation(value: string): string {
  return value.replace(/[),.;:!?]+$/g, "");
}
