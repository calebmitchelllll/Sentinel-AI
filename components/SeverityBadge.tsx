import { SEVERITY_COLORS, type Severity } from "@/lib/types";

export default function SeverityBadge({
  severity,
  size = "md",
}: {
  severity: Severity | string | null;
  size?: "sm" | "md" | "lg";
}) {
  const sev = (severity || "Medium") as Severity;
  const color = SEVERITY_COLORS[sev] || "#eab308";
  const px = size === "sm" ? "px-1.5 py-0.5 text-[10px]" : size === "lg" ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase rounded ${px}`}
      style={{ color, borderColor: color + "55", backgroundColor: color + "15", border: "1px solid" }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
      {sev}
    </span>
  );
}
