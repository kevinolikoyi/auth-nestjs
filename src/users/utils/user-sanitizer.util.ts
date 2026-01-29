/**
 * Utilitaire pour exclure les champs sensibles des objets User
 * Ne jamais retourner password, refreshToken, emailVerificationToken, passwordResetToken dans les réponses API
 */

type SensitiveUserKeys =
  | 'password'
  | 'refreshToken'
  | 'emailVerificationToken'
  | 'passwordResetToken'
  | 'passwordResetExpires';

export function sanitizeUser<
  T extends Record<string, unknown> | null | undefined,
>(user: T): T extends Record<string, unknown> ? Omit<T, SensitiveUserKeys> : T {
  if (!user) {
    return user as T extends Record<string, unknown>
      ? Omit<T, SensitiveUserKeys>
      : T;
  }

  const {
    password,
    refreshToken,
    emailVerificationToken,
    passwordResetToken,
    passwordResetExpires,
    ...sanitized
  } = user;

  void password;
  void refreshToken;
  void emailVerificationToken;
  void passwordResetToken;
  void passwordResetExpires;

  return sanitized as T extends Record<string, unknown>
    ? Omit<T, SensitiveUserKeys>
    : T;
}

export function sanitizeUsers<
  T extends Array<Record<string, unknown>> | null | undefined,
>(
  users: T,
): T extends Array<Record<string, unknown>>
  ? Array<Omit<T[number], SensitiveUserKeys>>
  : T {
  if (!users || !Array.isArray(users)) {
    return users as T extends Array<Record<string, unknown>>
      ? Array<Omit<T[number], SensitiveUserKeys>>
      : T;
  }

  return users.map((user) => sanitizeUser(user)) as T extends Array<
    Record<string, unknown>
  >
    ? Array<Omit<T[number], SensitiveUserKeys>>
    : T;
}
