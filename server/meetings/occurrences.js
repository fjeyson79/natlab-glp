'use strict';
// ============================================================================
// Group Meetings — central occurrence service.
//
// Every change to a meeting occurrence goes through this module, and each one
// produces a single domain event ('meeting.scheduled', 'meeting.rescheduled',
// 'meeting.postponed', 'meeting.cancelled'). A future, separately authorized
// release may attach e-mail (server/notify.js) through `onEvent`.
//
// R1: `onEvent` defaults to a no-op. Nothing here sends e-mail, schedules jobs
// or contacts any external service. Event delivery can never fail or delay
// the operation (errors are swallowed and logged without personal data).
// IN_PROGRESS / COMPLETED (start / end scientific meeting) arrive in R3.
// ============================================================================
const policy = require('./policy');

function makeOccurrenceService(repo, { onEvent } = {}) {
    const emit = (event, occurrence, group) => {
        if (typeof onEvent !== 'function') return;
        try {
            Promise.resolve(onEvent({ event, occurrence_id: occurrence.id, group_code: group && group.code }))
                .catch(() => console.warn(`[GROUP-MEETINGS] event hook failed event=${event}`));
        } catch (_) {
            console.warn(`[GROUP-MEETINGS] event hook failed event=${event}`);
        }
    };

    return {
        async schedule(group, { scheduledStart, durationMinutes, note }, actor) {
            const occ = await repo.insertOccurrence({
                groupId: group.id, scheduledStart, durationMinutes, note, actorId: actor.id,
            });
            emit('meeting.scheduled', occ, group);
            return { ok: true, occurrence: occ };
        },

        async apply(occurrence, action, { scheduledStart = null, note = null } = {}, actor) {
            const plan = policy.planOccurrenceAction(occurrence.status, action);
            if (!plan.ok) return { ok: false, status: 409, error: 'This change is not possible for the meeting in its current state.' };
            if (action === 'reschedule' && !scheduledStart) return { ok: false, status: 400, error: 'A valid scheduled_start is required.' };
            const updated = await repo.transitionOccurrence({
                id: occurrence.id, fromStatus: occurrence.status, toStatus: plan.to,
                scheduledStart: action === 'reschedule' ? scheduledStart : null, note, actorId: actor.id,
            });
            if (!updated) return { ok: false, status: 409, error: 'The meeting was changed by another request. Reload and try again.' };
            emit(plan.event, updated, { code: occurrence.group_code });
            return { ok: true, occurrence: updated };
        },
    };
}

module.exports = { makeOccurrenceService };
