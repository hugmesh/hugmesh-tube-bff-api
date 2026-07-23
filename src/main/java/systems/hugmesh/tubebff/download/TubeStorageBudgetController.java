package systems.hugmesh.tubebff.download;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.tubebff.security.PrincipalDomain;

/**
 * The ADMIN storage-budget surface — set a user's download storage budget cap. Mounted
 * under {@code /bff/tube/admin/**}, which {@link systems.hugmesh.tubebff.config.SecurityConfig}
 * gates to {@code ADMIN | SUPERADMIN} (with the role-hierarchy edge), so the path gate is
 * ADMIN end-to-end AND the method-level {@link #TUBE_BUDGET} @PreAuthorize re-checks
 * (defence in depth).
 *
 * <p><b>Domain server-derived.</b> An admin acts only WITHIN their own brand: the budget
 * row's {@code domain} is the acting admin's issuer-derived brand (NEVER a request field),
 * so a scoped admin of brand X can only set budgets for brand X's users; SUPERADMIN is
 * pinned to the platform default domain here (the budget plane is per-brand, not the
 * cross-domain access bypass). The TARGET user subject is carried in the body (an admin
 * acts ON another user).
 */
@Tag(name = "Tube Storage Budget (admin)", description = "ADMIN sets a user's download "
        + "storage budget cap (ADMIN|SUPERADMIN). Brand server-derived (own-brand only).")
@RestController
@RequestMapping("/bff/tube/admin/storage-budget")
@Validated
public class TubeStorageBudgetController {

    /** TUBE_BUDGET — set a user's storage budget: ADMIN or SUPERADMIN. */
    public static final String TUBE_BUDGET = "hasRole('ADMIN') or hasRole('SUPERADMIN')";

    private final StorageUsageService usage;
    private final PrincipalDomain principalDomain;

    public TubeStorageBudgetController(StorageUsageService usage, PrincipalDomain principalDomain) {
        this.usage = usage;
        this.principalDomain = principalDomain;
    }

    /**
     * Set the download storage budget cap for a target user. The acting admin's brand is
     * derived server-side; a scoped ADMIN can only set budgets for users in their own brand.
     * A negative {@code budgetBytes} is clamped to 0, immediately pausing all downloads
     * for that user.
     *
     * @param body the budget request — target {@code userSubject} and {@code budgetBytes};
     *             domain is NEVER read from the body (server-derived)
     * @param auth the acting admin's authentication
     * @return a {@code Mono} emitting the updated {@link TubeDownloadDto.Usage} row
     */
    @Operation(operationId = "setStorageBudget",
            summary = "Set a target user's download storage budget (bytes). "
            + "ADMIN/SUPERADMIN, own-brand (brand server-derived).")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Updated storage usage row"),
        @ApiResponse(responseCode = "400", description = "Validation failure (budgetBytes must be >= 0)"),
        @ApiResponse(responseCode = "401", description = "Missing or invalid JWT"),
        @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_ADMIN or ROLE_SUPERADMIN"),
        @ApiResponse(responseCode = "500", description = "Unexpected server error")
    })
    @PreAuthorize(TUBE_BUDGET)
    @PostMapping
    public Mono<TubeDownloadDto.Usage> setBudget(
            @Valid @RequestBody TubeDownloadDto.BudgetRequest body, Authentication auth) {
        String domain = adminBrand(auth);
        return usage.setBudget(body.userSubject(), domain, body.budgetBytes())
                .map(TubeDownloadDto.Usage::of);
    }

    /** The acting admin's brand, derived SERVER-SIDE from the validated issuer. A scoped
     *  admin governs only their own brand; a SUPERADMIN (forScope -> null cross-domain
     *  bypass) is pinned to the platform default domain on this per-brand budget plane. */
    private String adminBrand(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String d = principalDomain.forScope(jwt);
            return d == null ? DomainRegistry.DEFAULT_DOMAIN : d;
        }
        return DomainRegistry.DEFAULT_DOMAIN;
    }
}
