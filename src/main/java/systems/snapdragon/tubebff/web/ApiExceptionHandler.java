package systems.snapdragon.tubebff.web;

import systems.snapdragon.commons.web.ApiException;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Renders {@link ApiException} as the {@code {"error": message}} JSON body (and
 * the carried status) the UIs read, AND maps jakarta Bean Validation failures to a
 * clean {@code 400} in the SAME shape (with a {@code fields} map of per-field
 * errors). Works unchanged under WebFlux: {@code @RestControllerAdvice} +
 * {@code @ExceptionHandler} returning a {@code ResponseEntity} is handled
 * reactively (a controller's {@code Mono.error(...)} is routed here).
 *
 * <p>Validation shapes handled (the security-hardening "Bean Validation on all
 * paths" task):
 * <ul>
 *   <li>{@link WebExchangeBindException} — a {@code @Valid @RequestBody} DTO whose
 *       field constraints failed;</li>
 *   <li>{@link ConstraintViolationException} — a {@code @Validated} controller's
 *       {@code @PathVariable}/{@code @RequestParam} constraint failed;</li>
 *   <li>{@link ServerWebInputException} — a malformed/missing body or an
 *       unparseable param (surface as 400, not 500).</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    // ---- Exception handlers ----

    /**
     * Render an {@link ApiException} from the service layer with its carried HTTP status
     * and message — the fast path used by every controller error (403, 409, 400, 502, …).
     *
     * @param ex the application exception
     * @return a JSON response body {@code {"error": message}} with the carried status
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        return ResponseEntity.status(ex.status()).body(Map.of("error", ex.getMessage()));
    }

    /**
     * A {@code @Valid @RequestBody} DTO failed field-level constraints. Renders a
     * {@code {"error": "validation failed", "fields": {"field": "message", ...}}} 400
     * with one entry per violating field (sorted for deterministic UI display).
     *
     * @param ex the bind exception carrying the field errors
     * @return 400 with the per-field error map
     */
    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, Object>> handleBodyValidation(WebExchangeBindException ex) {
        Map<String, String> fields = new TreeMap<>();
        ex.getFieldErrors().forEach(fe ->
                fields.putIfAbsent(fe.getField(), fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage()));
        return badRequest(fields);
    }

    /**
     * A {@code @Validated} controller's {@code @PathVariable} or {@code @RequestParam}
     * constraint failed. Renders the same field-error map as the body-validation handler.
     *
     * @param ex the constraint violation exception
     * @return 400 with the per-param violation map
     */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleParamValidation(ConstraintViolationException ex) {
        Map<String, String> fields = new TreeMap<>();
        ex.getConstraintViolations().forEach(v ->
                fields.putIfAbsent(lastNode(v), v.getMessage()));
        return badRequest(fields);
    }

    /**
     * A malformed/missing body or an unparseable param (e.g. wrong content-type, a
     * missing required body) — 400, not 500. {@link WebExchangeBindException}
     * subclasses this, so the more-specific handler above wins for DTO validation.
     */
    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<Map<String, Object>> handleInput(ServerWebInputException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("detail", ex.getReason() == null ? "malformed request" : ex.getReason());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    // ---- Private helpers ----

    /**
     * Build the shared {@code {"error": "validation failed", "fields": ...}} 400 body.
     *
     * @param fields the per-field (or per-param) violation messages
     * @return a 400 {@link ResponseEntity} with the body
     */
    private static ResponseEntity<Map<String, Object>> badRequest(Map<String, String> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("fields", fields);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    /**
     * Extract the leaf property name from a constraint-violation path, e.g.
     * {@code "claim"} from {@code "handleParamValidation.claim"}. Used as the map key
     * for the per-param violation message.
     *
     * @param v the constraint violation
     * @return the leaf node of {@link ConstraintViolation#getPropertyPath()}
     */
    private static String lastNode(ConstraintViolation<?> v) {
        String path = v.getPropertyPath().toString();
        int dot = path.lastIndexOf('.');
        return dot >= 0 ? path.substring(dot + 1) : path;
    }
}
