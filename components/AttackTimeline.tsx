export default function AttackTimeline({
  timeline,
}: {
  timeline: Array<{ at: string; event: string }> | null | undefined;
}) {
  const items = timeline || [];
  if (items.length === 0) {
    return <p className="text-ink-dim text-sm font-mono">No timeline available.</p>;
  }

  return (
    <ol className="relative border-l border-line ml-2 mt-2">
      {items.map((item, idx) => {
        const isCritical = /admin|exfil|critical|sensitive|attach/i.test(item.event);
        const color = isCritical ? "#ef4444" : "#60a5fa";
        return (
          <li key={idx} className="mb-4 ml-5">
            <span
              className="absolute -left-[7px] w-3.5 h-3.5 rounded-full border-2"
              style={{ backgroundColor: color, borderColor: "#0a0e14" }}
            />
            <div className="font-mono text-[11px] text-ink-faint">{item.at || `step ${idx + 1}`}</div>
            <div className="text-ink text-sm">{item.event}</div>
          </li>
        );
      })}
    </ol>
  );
}
