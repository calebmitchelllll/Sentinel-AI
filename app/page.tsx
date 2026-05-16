import { redirect } from "next/navigation";
import { getSession } from "@/lib/supabase-server";

export default async function Home() {
  const session = await getSession();
  if (session) redirect("/dashboard");
  redirect("/auth/signin");
}
