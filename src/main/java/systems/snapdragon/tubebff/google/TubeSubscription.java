package systems.snapdragon.tubebff.google;

import java.time.Instant;

/**
 * A single {@code tube_subscription} row — one of a connected user's subscribed YouTube
 * channels (schema in Liquibase {@code db/changelog/006-tube-subscription.xml}).
 * {@code domain} + {@code userSubject} scope it to the owning (brand,user); the
 * {@code channelId} is unique within that scope (the sync UPSERTs in place).
 */
public record TubeSubscription(
        String id,
        String domain,
        String userSubject,
        String channelId,
        String channelTitle,
        String thumbnailUrl,
        Instant syncedAt) {
}
