package net.hugmesh.tubebff;

import net.hugmesh.tubebff.download.TubeDownloadDto;
import net.hugmesh.tubebff.google.GoogleApiClient;
import net.hugmesh.tubebff.google.TubeGoogleDto;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the defensive-copy contract of the three records that carry a mutable
 * {@link List} ({@code TubeDownloadDto.JobList}, {@code TubeGoogleDto.SubscriptionList},
 * {@code GoogleApiClient.SubscriptionsPage}), which is what clears SpotBugs
 * EI_EXPOSE_REP / EI_EXPOSE_REP2 for them:
 *
 * <ul>
 *   <li>the record keeps its OWN copy: a caller mutating the list it passed in later does
 *       not change the record;</li>
 *   <li>the accessor never hands out a mutable list;</li>
 *   <li>{@code null} stays {@code null} and {@code null} elements are tolerated — a
 *       malformed payload must not turn into an NPE (and so a 500), which is exactly what
 *       {@code List.copyOf} would do and why it is not used here.</li>
 * </ul>
 *
 * <p>The JSON wire shape is unchanged and stays covered by the controller tests
 * ({@code $.jobs[0]...}, {@code $.subscriptions[0]...}) and the committed-OpenAPI drift guard.
 */
class ListCarrierDefensiveCopyTest {

    @Test
    void jobListKeepsItsOwnReadOnlyCopy() {
        assertListContract(src -> new TubeDownloadDto.JobList(src)::jobs, job("j1"), job("j2"));
    }

    @Test
    void subscriptionListKeepsItsOwnReadOnlyCopy() {
        assertListContract(src -> new TubeGoogleDto.SubscriptionList(src)::subscriptions,
                subscription("c1"), subscription("c2"));
    }

    @Test
    void subscriptionsPageKeepsItsOwnReadOnlyCopy() {
        assertListContract(src -> new GoogleApiClient.SubscriptionsPage(src, "next")::items,
                pageItem("c1"), pageItem("c2"));
    }

    /**
     * @param carrier builds the record around the given list and returns its list accessor
     * @param first   an element to put in the list
     * @param second  a different element, used to mutate the caller's list afterwards
     */
    private static <T> void assertListContract(Function<List<T>, Supplier<List<T>>> carrier, T first, T second) {
        // The caller keeps mutating its own list: the record must not see it.
        List<T> source = new ArrayList<>(List.of(first));
        Supplier<List<T>> accessor = carrier.apply(source);
        source.add(second);
        assertThat(accessor.get()).containsExactly(first);

        // The accessor never hands out a list the caller could change.
        assertThatThrownBy(() -> accessor.get().add(second)).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> accessor.get().clear()).isInstanceOf(UnsupportedOperationException.class);

        // null stays null, and null elements are tolerated (List.copyOf would throw NPE on both).
        assertThat(carrier.apply(null).get()).isNull();
        assertThat(carrier.apply(Arrays.asList(first, null)).get()).containsExactly(first, null);
    }

    private static TubeDownloadDto.Job job(String id) {
        return new TubeDownloadDto.Job(id, "default", "alice", "chan", "vid", "title", "queued",
                null, null, 0, null, null, null, Instant.EPOCH, Instant.EPOCH);
    }

    private static TubeGoogleDto.Subscription subscription(String channelId) {
        return new TubeGoogleDto.Subscription(channelId, "title", "https://example.invalid/t.png", Instant.EPOCH);
    }

    private static GoogleApiClient.Subscription pageItem(String channelId) {
        return new GoogleApiClient.Subscription(channelId, "title", "https://example.invalid/t.png");
    }
}
