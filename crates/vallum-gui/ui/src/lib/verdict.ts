/** The verdict tones both the header and the health panel speak. Lives
 *  outside the component files so fast-refresh sees components only. */
export type VerdictTone = "live" | "stale" | "fault" | "muted"

/** One place maps a verdict tone to its class. */
export const verdictTone: Record<VerdictTone, string> = {
  live: "text-live",
  fault: "text-fault",
  stale: "text-stale",
  muted: "text-muted-foreground",
}
