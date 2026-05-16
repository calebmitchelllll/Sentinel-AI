export default function SimulatedAttackBadge({ size = "md" }: { size?: "sm" | "md" }) {
  const px =
    size === "sm"
      ? "px-1.5 py-0.5 text-[10px]"
      : "px-2 py-0.5 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase rounded ${px}`}
      style={{
        color: "#a855f7",
        borderColor: "#a855f755",
        backgroundColor: "#a855f715",
        border: "1px solid",
      }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: "#a855f7" }} />
      SIMULATED ATTACK
    </span>
  );
}
