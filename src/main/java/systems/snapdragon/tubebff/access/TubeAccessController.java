package systems.snapdragon.tubebff.access;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The use grant / timeout / ban OVERLAY surface — the write side of the
 * {@code tube_access} desired-state table that {@link TubeAccessGuard} enforces
 * (DEFAULT-DENY) on the use path.
 *
 * <p><b>ROLE MODEL.</b> {@code ROLE_TUBE} is the base service role (sibling of
 * {@code ROLE_OWNCAST} / {@code ROLE_WIKI} / {@code ROLE_FORUM}) — the gateway
 * route-access floor for the tube surface + the connect/view-own surface; it does NOT
 * by itself confer use (use is grant-only, enforced by {@link TubeAccessGuard}). The
 * governance write actions are gated one tier up:
 * <ul>
 *   <li>grant / timeout / ban / restore (revoke) — {@link #TUBE_GOVERN}
 *       (ADMIN | SUPERADMIN). Mounted under {@code /bff/tube/admin/access/**} so the
 *       SecurityConfig path gate is ADMIN|SUPERADMIN end-to-end AND the method-level
 *       {@code @PreAuthorize} re-checks (defence in depth). An ADMIN governs only WITHIN
 *       their own brand (server-derived domain); SUPERADMIN is cross-domain.</li>
 *   <li>list-all / history (manage-all) — {@link #TUBE_MANAGE} (SUPERADMIN), mounted
 *       under {@code /bff/tube/superadmin/access} so the path gate is SUPERADMIN.</li>
 * </ul>
 * Every write is DOMAIN-SCOPED in the service; {@code state=revoked} rows are RETAINED
 * (audit), never hard-deleted.
 *
 * <h2>Caller-role access matrix</h2>
 *
 * <pre>
 *  Path prefix                        │ Method         │ Min role
 *  ───────────────────────────────────┼────────────────┼──────────────────
 *  /bff/tube/admin/access/grant       │ POST           │ ADMIN | SUPERADMIN
 *  /bff/tube/admin/access/timeout     │ POST           │ ADMIN | SUPERADMIN
 *  /bff/tube/admin/access/ban         │ POST           │ ADMIN | SUPERADMIN
 *  /bff/tube/admin/access/{type}/{sub}│ DELETE         │ ADMIN | SUPERADMIN
 *  /bff/tube/superadmin/access        │ GET            │ SUPERADMIN
 *  /bff/tube/superadmin/access/{sub}  │ GET (history)  │ SUPERADMIN
 * </pre>
 *
 * @see TubeAccessGuard
 * @see TubeAccessService
 */
@Tag(name = "Tube Use Access", description = "Tube use grant/timeout/ban overlay "
        + "(tube_access): grant/timeout/ban/restore (TUBE_GOVERN), list-all/history "
        + "(TUBE_MANAGE). Domain-scoped; use is DEFAULT-DENY, enforced at request time "
        + "by TubeAccessGuard (an active use grant AND NOT an active ban, SUPERADMIN exempt).")
@RestController
@RequestMapping("/bff/tube")
@Validated
public class TubeAccessController {

    /** TUBE_GOVERN — grant/timeout/ban/restore may-use: ADMIN or SUPERADMIN.
     *  An admin decides which of their domain's users may use the tube service on a UI. */
    public static final String TUBE_GOVERN = "hasRole('ADMIN') or hasRole('SUPERADMIN')";

    /** TUBE_MANAGE — manage-all of the tube governance solution: SUPERADMIN only
     *  (list-all + history here; service enable per-domain + GPU check in PR7). */
    public static final String TUBE_MANAGE = "hasRole('SUPERADMIN')";

    private final TubeAccessService access;

    public TubeAccessController(TubeAccessService access) {
        this.access = access;
    }

    // ---- Grant / timeout / ban / restore (TUBE_GOVERN) ----

    /**
     * Grant a user permanent may-use access ({@code tube_access} use override). This is
     * the ONLY way to lift a user above the default-deny use floor — the bare
     * {@code ROLE_TUBE} does not confer use by itself. Idempotent when an active grant
     * already exists.
     *
     * @param body an object carrying {@code userSubject} (the target user's Casdoor sub)
     *             and optional {@code reason}; the actor's brand is server-derived
     * @param auth the acting admin's authentication
     * @return 200 with the active {@link TubeAccessDto.Access} row (new or existing)
     */
    @Operation(operationId = "grantUseAccess",
            summary = "GRANT a USER permanent may-use access (an active tube_access "
            + "use override) — the way to lift a user above the default-deny use floor. "
            + "ADMIN/SUPERADMIN, own-brand. Idempotent if already active.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Grant created or already active"),
        @ApiResponse(responseCode = "400", description = "Validation failure on request body"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_GOVERN)
    @PostMapping("/admin/access/grant")
    public Mono<ResponseEntity<TubeAccessDto.Access>> grant(
            @Valid @RequestBody TubeAccessDto.GrantOrBan body, Authentication auth) {
        return access.grant(body.userSubject(), body.reason(), auth)
                .map(a -> ResponseEntity.ok(TubeAccessDto.Access.of(a)));
    }

    /**
     * Timeout a user from the tube service for a bounded window. Creates an active
     * {@code banned} override with a future {@code expires_at}; the override stops
     * denying automatically once {@code expires_at <= now} without any additional write.
     * Idempotent when an active ban already exists.
     *
     * @param body carries {@code userSubject}, {@code ttlSeconds} (must be positive),
     *             and optional {@code reason}
     * @param auth the acting admin's authentication
     * @return 200 with the active ban row (new or existing)
     */
    @Operation(operationId = "timeoutUseAccess",
            summary = "TIMEOUT a USER from the tube service for a bounded window (an active "
            + "banned override with a future expires_at; auto-restores on expiry without "
            + "a write). ADMIN/SUPERADMIN, own-brand. Idempotent if already active.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Timeout override created"),
        @ApiResponse(responseCode = "400", description = "Validation failure (ttlSeconds must be positive)"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_GOVERN)
    @PostMapping("/admin/access/timeout")
    public Mono<ResponseEntity<TubeAccessDto.Access>> timeout(
            @Valid @RequestBody TubeAccessDto.Timeout body, Authentication auth) {
        return access.timeout(body.userSubject(), body.ttlSeconds(), body.reason(), auth)
                .map(a -> ResponseEntity.ok(TubeAccessDto.Access.of(a)));
    }

    /**
     * Ban a user from the tube service permanently ({@code expires_at} NULL). A ban
     * takes precedence over a co-existing grant (ban &gt; grant). Requires an explicit
     * {@link #revoke} to lift.
     *
     * @param body carries {@code userSubject} and optional {@code reason}
     * @param auth the acting admin's authentication
     * @return 200 with the active ban row (new or existing)
     */
    @Operation(operationId = "banUseAccess",
            summary = "BAN a USER from the tube service permanently (an active banned override, "
            + "expires_at NULL). Denies even an active grantee (ban>grant). Must be revoked "
            + "explicitly. ADMIN/SUPERADMIN, own-brand.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Ban override created"),
        @ApiResponse(responseCode = "400", description = "Validation failure on request body"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_GOVERN)
    @PostMapping("/admin/access/ban")
    public Mono<ResponseEntity<TubeAccessDto.Access>> ban(
            @Valid @RequestBody TubeAccessDto.GrantOrBan body, Authentication auth) {
        return access.ban(body.userSubject(), body.reason(), auth)
                .map(a -> ResponseEntity.ok(TubeAccessDto.Access.of(a)));
    }

    /**
     * Restore/revoke: CAS the active override of {@code accessType} to {@code revoked}
     * for {@code userSubject} (the row is retained = audit trail). A no-op when no
     * active override of that type exists. To restore use after a ban: revoke the
     * {@code banned} row. To remove a grant: revoke the {@code use} row.
     *
     * @param accessType  must be {@code "use"} or {@code "banned"}; other values yield 400
     * @param userSubject the Casdoor subject of the target user
     * @param auth        the acting admin's authentication
     * @return 200 with {@code {"state":"revoked","accessType":...,"userSubject":...}}
     *         on success; 400 when {@code accessType} is invalid
     */
    @Operation(operationId = "revokeUseAccess",
            summary = "RESTORE/REVOKE: CAS active->revoked for one override type for a user "
            + "(row retained = audit). accessType = use|banned: revoke 'banned' to restore use; "
            + "revoke 'use' to remove a grant. No-op if no active override exists. "
            + "ADMIN/SUPERADMIN, own-brand.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Override revoked (or no active override — no-op)"),
        @ApiResponse(responseCode = "400", description = "accessType must be 'use' or 'banned'"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_GOVERN)
    @DeleteMapping("/admin/access/{accessType}/{userSubject}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @PathVariable String accessType, @PathVariable String userSubject, Authentication auth) {
        // Reject any accessType that is not one of the two known values before touching
        // the DB — a 400 here is preferable to an empty no-op for a typo.
        String type = switch (accessType) {
            case TubeAccess.TYPE_USE    -> TubeAccess.TYPE_USE;
            case TubeAccess.TYPE_BANNED -> TubeAccess.TYPE_BANNED;
            default                     -> null;
        };
        if (type == null) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "error", "accessType must be 'use' or 'banned'")));
        }
        return access.revoke(userSubject, type, auth)
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of(
                        "state", "revoked", "accessType", type, "userSubject", userSubject)));
    }

    // ---- Manage-all (TUBE_MANAGE) ----

    /**
     * List all active {@code tube_access} overrides. A scoped ADMIN sees only their
     * brand's rows (domain server-derived); SUPERADMIN sees all brands.
     *
     * @param auth the acting superadmin's authentication
     * @return a {@link TubeAccessDto.AccessList} wrapping all currently active rows
     */
    @Operation(operationId = "listActiveUseAccess",
            summary = "List all ACTIVE tube_access overrides (scoped to the caller's "
            + "brand; SUPERADMIN sees all brands). SUPERADMIN only.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Active override list"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_MANAGE)
    @GetMapping("/superadmin/access")
    public Mono<TubeAccessDto.AccessList> listActive(Authentication auth) {
        return access.listActive(auth).map(TubeAccessDto.Access::of)
                .collectList().map(TubeAccessDto.AccessList::new);
    }

    /**
     * The full history (active + revoked = audit trail) of all tube_access overrides
     * for a principal. Revoked rows are retained, never hard-deleted.
     *
     * @param userSubject the Casdoor subject of the user to audit
     * @param auth        the acting superadmin's authentication
     * @return a {@link TubeAccessDto.AccessList} of all rows (active and revoked),
     *         newest first
     */
    @Operation(operationId = "useAccessHistory",
            summary = "The full grant/timeout/ban HISTORY (active + revoked = audit trail) "
            + "for a principal (scoped to the caller's brand; SUPERADMIN sees all). "
            + "Revoked rows are retained (never deleted). SUPERADMIN only.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "History list (may be empty)"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_MANAGE)
    @GetMapping("/superadmin/access/{userSubject}/history")
    public Mono<TubeAccessDto.AccessList> history(@PathVariable String userSubject, Authentication auth) {
        return access.historyFor(userSubject, auth).map(TubeAccessDto.Access::of)
                .collectList().map(TubeAccessDto.AccessList::new);
    }
}
