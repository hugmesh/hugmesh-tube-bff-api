package systems.snapdragon.tubebff.security;

/**
 * The scoped-vs-unscoped decision for every per-domain repository — the data-layer half
 * of the multi-brand isolation boundary. COPIED (logic) from the snapdragon-forum-bff-api
 * {@code DomainScope} (package adjusted).
 *
 * <p><b>Convention.</b> The service/controller layer resolves the principal's domain
 * from the validated token issuer ({@link PrincipalDomain#forScope}) and passes it
 * down; each repository then dispatches via {@link #isUnscoped(String)} onto one of a
 * derived-finder pair:
 * <ul>
 *   <li>a NON-null {@code domain} ⇒ the {@code ...AndDomain...} derived finder is used,
 *       so the caller only ever touches rows in their OWN brand;</li>
 *   <li>a {@code null} {@code domain} ⇒ the un-pinned finder (no domain predicate) is
 *       used — this is the SUPERADMIN (cross-domain infra super-role) bypass:
 *       SUPERADMIN sees/mutates every brand's tube access overrides (e.g. the
 *       whole-platform tube governance across all brands). The caller decides this (it
 *       passes {@code null} only for a SUPERADMIN principal); a non-SUPERADMIN caller is
 *       ALWAYS passed its concrete domain.</li>
 * </ul>
 *
 * <p>Domain is ALWAYS an ADDITIONAL predicate alongside any existing owner/target one
 * — it never replaces or weakens owner-tracking (user_subject == the targeted USER). A
 * scoped ADMIN of brand X sees ONLY brand X's overrides.
 *
 * <p><b>Data-access standard (2026-06-18).</b> The former raw-SQL helpers
 * ({@code andPredicate}/{@code bind}/{@code PARAM}, which spliced {@code AND domain =
 * :domain} into a {@code DatabaseClient} {@code GenericExecuteSpec}) were removed once
 * every site moved to Spring Data R2DBC derived finders; the scope decision now lives
 * solely in {@link #isUnscoped(String)}, which the repositories branch on.
 */
public final class DomainScope {

    private DomainScope() {}

    /** True iff the domain represents the SUPERADMIN cross-domain bypass (null/blank
     *  ⇒ no predicate — the un-pinned derived finder is used). */
    public static boolean isUnscoped(String domain) {
        return domain == null || domain.isBlank();
    }
}
