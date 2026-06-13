package systems.snapdragon.tubebff.download;

import java.time.Instant;

/**
 * A single {@code tube_subscription} row — a per-user subscribed YouTube channel (schema
 * in Liquibase {@code db/changelog/006-tube-subscription.xml}). This is the minimal
 * content model the download work-queue reads as its ENQUEUE SOURCE: for each of the
 * owner's subscribed channels with a known latest video, the queue enqueues a download
 * job (deduped on the video id).
 *
 * <p>The full Google-OAuth subscriptions sync that POPULATES this table from the user's
 * YouTube account is the separate Google-connect path; here it is just the model the
 * enqueue reads. DOMAIN-scoped: {@code domain} stamped SERVER-SIDE from the validated
 * issuer; one row per (domain, user_subject, channel_id).
 */
public record TubeSubscription(
        String id,
        String domain,
        String userSubject,
        String channelId,
        String channelTitle,
        String latestVideoId,
        String latestVideoTitle,
        Instant createdAt,
        Instant updatedAt) {
}
