/**
 * Utilitaire pour exclure les champs sensibles des objets User
 * Ne jamais retourner password, refreshToken, emailVerificationToken, passwordResetToken dans les réponses API
 */

export function sanitizeUser(user: any) {
    if (!user) {
        return user;
    }

    const {
        password,
        refreshToken,
        emailVerificationToken,
        passwordResetToken,
        passwordResetExpires,
        ...sanitized
    } = user;

    return sanitized;
}

export function sanitizeUsers(users: any[]) {
    if (!users || !Array.isArray(users)) {
        return users;
    }

    return users.map((user) => sanitizeUser(user));
}
