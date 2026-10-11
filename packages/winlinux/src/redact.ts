// Redaction rule: the password, its base64, and the base64
// Basic token `user:password` become `***`. An empty password redacts nothing.
export interface RedactSecrets {
  username: string;
  password?: string;
}

export function redact(text: string, secrets: RedactSecrets): string {
  const password = secrets.password;
  if (!password) return text;
  const needles = [
    Buffer.from(`${secrets.username}:${password}`, 'utf8').toString('base64'),
    Buffer.from(password, 'utf8').toString('base64'),
    password,
  ];
  let out = text;
  for (const needle of needles) out = out.split(needle).join('***');
  return out;
}
