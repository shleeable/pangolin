import {
    encodeBase32LowerCaseNoPadding,
    encodeHexLowerCase
} from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";
import {
    resourceSessions,
    safeRead,
    Session,
    sessions,
    User,
    users
} from "@server/db";
import { db } from "@server/db";
import { and, eq, inArray, ne } from "drizzle-orm";
import config from "@server/lib/config";
import type { RandomReader } from "@oslojs/crypto/random";
import { generateRandomString } from "@oslojs/crypto/random";
import logger from "@server/logger";
import { localCache } from "@server/lib/cache";

export const SESSION_COOKIE_NAME =
    config.getRawConfig().server.session_cookie_name;
export const SESSION_COOKIE_EXPIRES =
    1000 *
    60 *
    60 *
    config.getRawConfig().server.dashboard_session_length_hours;
export const COOKIE_DOMAIN = config.getRawConfig().app.dashboard_url
    ? new URL(config.getRawConfig().app.dashboard_url!).hostname
    : undefined;

export function generateSessionToken(): string {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    const token = encodeBase32LowerCaseNoPadding(bytes);
    return token;
}

export async function createSession(
    token: string,
    userId: string
): Promise<Session> {
    const sessionId = encodeHexLowerCase(
        sha256(new TextEncoder().encode(token))
    );
    const [session] = await db
        .insert(sessions)
        .values({
            sessionId: sessionId,
            userId,
            expiresAt: new Date(Date.now() + SESSION_COOKIE_EXPIRES).getTime(),
            issuedAt: new Date().getTime()
        })
        .returning();
    return session;
}

export async function validateSessionToken(
    token: string
): Promise<SessionValidationResult> {
    const sessionId = encodeHexLowerCase(
        sha256(new TextEncoder().encode(token))
    );

    const cacheKey = `userSession:${sessionId}`;
    const cached = localCache.get<SessionValidationResult>(cacheKey);
    if (cached !== undefined) {
        return cached;
    }

    const result = await safeRead((db) =>
        db
            .select({ user: users, session: sessions })
            .from(sessions)
            .innerJoin(users, eq(sessions.userId, users.userId))
            .where(eq(sessions.sessionId, sessionId))
    );

    if (result.length < 1) {
        const val = { session: null, user: null };
        localCache.set(cacheKey, val, 5); // Cache negative result for 5 seconds
        return val;
    }
    const { user, session } = result[0];
    if (Date.now() >= session.expiresAt) {
        await db
            .delete(sessions)
            .where(eq(sessions.sessionId, session.sessionId));
        const val = { session: null, user: null };
        localCache.set(cacheKey, val, 5);
        return val;
    }
    if (Date.now() >= session.expiresAt - SESSION_COOKIE_EXPIRES / 2) {
        session.expiresAt = new Date(
            Date.now() + SESSION_COOKIE_EXPIRES
        ).getTime();
        await db.transaction(async (trx) => {
            await trx
                .update(sessions)
                .set({
                    expiresAt: session.expiresAt
                })
                .where(eq(sessions.sessionId, session.sessionId));

            await trx
                .update(resourceSessions)
                .set({
                    expiresAt: session.expiresAt
                })
                .where(eq(resourceSessions.userSessionId, session.sessionId));
        });
    }
    const val = { session, user };
    localCache.set(cacheKey, val, 5); // Cache valid session for 5 seconds
    return val;
}

export async function invalidateSession(sessionId: string): Promise<void> {
    try {
        localCache.del(`userSession:${sessionId}`);
        await db.transaction(async (trx) => {
            await trx
                .delete(resourceSessions)
                .where(eq(resourceSessions.userSessionId, sessionId));
            await trx.delete(sessions).where(eq(sessions.sessionId, sessionId));
        });
    } catch (e) {
        logger.error("Failed to invalidate session", e);
    }
}

export async function invalidateAllSessions(userId: string): Promise<void> {
    try {
        // Query the database outside the transaction to fetch active sessions and delete them from cache
        const userSessions = await db
            .select()
            .from(sessions)
            .where(eq(sessions.userId, userId));
        for (const s of userSessions) {
            localCache.del(`userSession:${s.sessionId}`);
        }

        await db.transaction(async (trx) => {
            const userSessions = await trx
                .select()
                .from(sessions)
                .where(eq(sessions.userId, userId));
            await trx.delete(resourceSessions).where(
                inArray(
                    resourceSessions.userSessionId,
                    userSessions.map((s) => s.sessionId)
                )
            );
            await trx.delete(sessions).where(eq(sessions.userId, userId));
        });
    } catch (e) {
        logger.error("Failed to all invalidate user sessions", e);
    }
}

export async function invalidateAllSessionsExceptCurrent(
    userId: string,
    currentSessionId: string
): Promise<void> {
    try {
        // Query the database outside the transaction to fetch active sessions except current and delete them from cache
        const userSessions = await db
            .select()
            .from(sessions)
            .where(
                and(
                    eq(sessions.userId, userId),
                    ne(sessions.sessionId, currentSessionId)
                )
            );
        for (const s of userSessions) {
            localCache.del(`userSession:${s.sessionId}`);
        }

        await db.transaction(async (trx) => {
            const userSessions = await trx
                .select()
                .from(sessions)
                .where(
                    and(
                        eq(sessions.userId, userId),
                        ne(sessions.sessionId, currentSessionId)
                    )
                );

            if (userSessions.length > 0) {
                await trx.delete(resourceSessions).where(
                    inArray(
                        resourceSessions.userSessionId,
                        userSessions.map((s) => s.sessionId)
                    )
                );
            }

            await trx
                .delete(sessions)
                .where(
                    and(
                        eq(sessions.userId, userId),
                        ne(sessions.sessionId, currentSessionId)
                    )
                );
        });
    } catch (e) {
        logger.error("Failed to invalidate user sessions except current", e);
    }
}

export function serializeSessionCookie(
    token: string,
    isSecure: boolean,
    expiresAt: Date
): string {
    if (isSecure) {
        return `${SESSION_COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Expires=${expiresAt.toUTCString()}; Path=/; Secure; Domain=${COOKIE_DOMAIN}`;
    } else {
        return `${SESSION_COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Expires=${expiresAt.toUTCString()}; Path=/;`;
    }
}

export function createBlankSessionTokenCookie(isSecure: boolean): string {
    if (isSecure) {
        return `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/; Secure; Domain=${COOKIE_DOMAIN}`;
    } else {
        return `${SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/;`;
    }
}

const random: RandomReader = {
    read(bytes: Uint8Array): void {
        crypto.getRandomValues(bytes);
    }
};

export function generateId(length: number): string {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    return generateRandomString(random, alphabet, length);
}

export function generateIdFromEntropySize(size: number): string {
    const buffer = crypto.getRandomValues(new Uint8Array(size));
    return encodeBase32LowerCaseNoPadding(buffer);
}

export type SessionValidationResult =
    | { session: Session; user: User }
    | { session: null; user: null };
