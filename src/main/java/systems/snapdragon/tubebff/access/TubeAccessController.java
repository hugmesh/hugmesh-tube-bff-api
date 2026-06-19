package systems.snapdragon.tubebff.access;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The use grant / timeout / ban OVERLAY surface — the write side of the
 * {@code tube_access} desired-state that {@link TubeAccessGuard} enforces
 * (DEFAULT-DENY) on the use path. CLONED in role model from the owncast-bff
 * {@code OwncastBroadcastController}.
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

    // ── grant / timeout / ban / restore (TUBE_GOVERN) ──────────────────

    @Operation(operationId = "grantUseAccess",
            summary = "GRANT a USER permanent may-use access (an active tube_access "
            + "use override) — the way to lift a user above the default-deny use floor. "
            + "ADMIN/SUPERADMIN, own-brand.")
    @PreAuthorize(TUBE_GOVERN)
    @PostMapping("/admin/access/grant")
    public Mono<ResponseEntity<TubeAccessDto.Access>> grant(
            @Valid @RequestBody TubeAccessDto.GrantOrBan body, Authentication auth) {
        return access.grant(body.userSubject(), body.reason(), auth)
                .map(a -> ResponseEntity.ok(TubeAccessDto.Access.of(a)));
    }

    @Operation(operationId = "timeoutUseAccess",
            summary = "TIMEOUT a USER from the tube service for a bounded window (an active "
            + "banned override with a future expires_at; auto-restores on expiry). "
            + "ADMIN/SUPERADMIN, own-brand.")
    @PreAuthorize(TUBE_GOVERN)
    @PostMapping("/admin/access/timeout")
    public Mono<ResponseEntity<TubeAccessDto.Access>> timeout(
            @Valid @RequestBody TubeAccessDto.Timeout body, Authentication auth) {
        return access.timeout(body.userSubject(), body.ttlSeconds(), body.reason(), auth)
                .map(a -> ResponseEntity.ok(TubeAccessDto.Access.of(a)));
    }

    @Operation(operationId = "banUseAccess",
            summary = "BAN a USER from the tube service permanently (an active banned override, "
            + "expires_at NULL). Denies even an active grantee (ban>grant). ADMIN/SUPERADMIN, "
            + "own-brand.")
    @PreAuthorize(TUBE_GOVERN)
    @PostMapping("/admin/access/ban")
    public Mono<ResponseEntity<TubeAccessDto.Access>> ban(
            @Valid @RequestBody TubeAccessDto.GrantOrBan body, Authentication auth) {
        return access.ban(body.userSubject(), body.reason(), auth)
                .map(a -> ResponseEntity.ok(TubeAccessDto.Access.of(a)));
    }

    @Operation(operationId = "revokeUseAccess",
            summary = "RESTORE/REVOKE: lift the active override of a type for a user "
            + "(CAS active->revoked; the row is retained = audit). accessType = use|banned: "
            + "revoke 'banned' to restore use; revoke 'use' to remove a grant. "
            + "ADMIN/SUPERADMIN, own-brand.")
    @PreAuthorize(TUBE_GOVERN)
    @DeleteMapping("/admin/access/{accessType}/{userSubject}")
    public Mono<ResponseEntity<Map<String, Object>>> revoke(
            @PathVariable String accessType, @PathVariable String userSubject, Authentication auth) {
        String type = TubeAccess.TYPE_USE.equals(accessType) ? TubeAccess.TYPE_USE
                : TubeAccess.TYPE_BANNED.equals(accessType) ? TubeAccess.TYPE_BANNED : null;
        if (type == null) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "error", "accessType must be 'use' or 'banned'")));
        }
        return access.revoke(userSubject, type, auth)
                .thenReturn(ResponseEntity.ok(Map.<String, Object>of(
                        "state", "revoked", "accessType", type, "userSubject", userSubject)));
    }

    // ── manage-all (TUBE_MANAGE) ───────────────────────────────────────

    @Operation(operationId = "listActiveUseAccess",
            summary = "List all ACTIVE tube_access overrides (scoped to the caller's "
            + "brand; SUPERADMIN sees all). SUPERADMIN.")
    @PreAuthorize(TUBE_MANAGE)
    @GetMapping("/superadmin/access")
    public Mono<TubeAccessDto.AccessList> listActive(Authentication auth) {
        return access.listActive(auth).map(TubeAccessDto.Access::of)
                .collectList().map(TubeAccessDto.AccessList::new);
    }

    @Operation(operationId = "useAccessHistory",
            summary = "The full grant/timeout/ban HISTORY (active + revoked = audit) for "
            + "a principal (scoped to the caller's brand; SUPERADMIN sees all). SUPERADMIN.")
    @PreAuthorize(TUBE_MANAGE)
    @GetMapping("/superadmin/access/{userSubject}/history")
    public Mono<TubeAccessDto.AccessList> history(@PathVariable String userSubject, Authentication auth) {
        return access.historyFor(userSubject, auth).map(TubeAccessDto.Access::of)
                .collectList().map(TubeAccessDto.AccessList::new);
    }
}
