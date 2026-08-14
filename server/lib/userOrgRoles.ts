import { db, roles, userOrgRoles } from "@server/db";
import { and, eq } from "drizzle-orm";
import { localCache } from "@server/lib/cache";

/**
 * Get all role IDs a user has in an organization.
 * Returns empty array if the user has no roles in the org (callers must treat as no access).
 */
export async function getUserOrgRoleIds(
    userId: string,
    orgId: string
): Promise<number[]> {
    const cacheKey = `userOrgRoleIds:${userId}:${orgId}`;
    const cached = localCache.get<number[]>(cacheKey);
    if (cached !== undefined) {
        return cached;
    }

    const rows = await db
        .select({ roleId: userOrgRoles.roleId })
        .from(userOrgRoles)
        .where(
            and(eq(userOrgRoles.userId, userId), eq(userOrgRoles.orgId, orgId))
        );
    const result = rows.map((r) => r.roleId);
    localCache.set(cacheKey, result, 10); // Cache for 10 seconds
    return result;
}

export async function getUserOrgRoles(
    userId: string,
    orgId: string
): Promise<{ roleId: number; roleName: string }[]> {
    const cacheKey = `userOrgRoles:${userId}:${orgId}`;
    const cached =
        localCache.get<{ roleId: number; roleName: string }[]>(cacheKey);
    if (cached !== undefined) {
        return cached;
    }

    const rows = await db
        .select({ roleId: userOrgRoles.roleId, roleName: roles.name })
        .from(userOrgRoles)
        .innerJoin(roles, eq(userOrgRoles.roleId, roles.roleId))
        .where(
            and(eq(userOrgRoles.userId, userId), eq(userOrgRoles.orgId, orgId))
        );
    localCache.set(cacheKey, rows, 10); // Cache for 10 seconds
    return rows;
}
