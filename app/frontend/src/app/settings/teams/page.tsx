"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import Link from "next/link";
import { getQuickexApiBase } from "@/lib/api";
import { fetchWithAuth } from "@/lib/api";

interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: "admin" | "operator" | "viewer";
  status: "active" | "pending";
}

type TeamResponse = { members: TeamMember[]; currentRole: "admin" | "member" | "read_only" };
type TeamRole = TeamMember["role"];

async function teamRequest<T>(path: string, apiKey: string, init?: RequestInit): Promise<T> {
  const response = await fetchWithAuth(`${getQuickexApiBase()}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", "x-api-key": apiKey, ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body?.message ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export default function TeamSettings() {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [userRole, setUserRole] = useState<"admin" | "member" | "read_only">("read_only");
  const [apiKey, setApiKey] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteName, setInviteName] = useState("");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamRole>("viewer");

  const loadMembers = useCallback(async () => {
    const key = window.sessionStorage.getItem("quickex.apiKey") ?? "";
    setApiKey(key);
    if (!key) {
      setError("Connect an organization-scoped API key to manage team members.");
      setLoading(false);
      return;
    }
    try {
      const data = await teamRequest<TeamResponse>("/teams", key);
      setMembers(data.members);
      setUserRole(data.currentRole);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void loadMembers(); }, [loadMembers]);

  const handleRoleChange = async (memberId: string, newRole: TeamRole) => {
    const previous = members;
    setMembers(members.map((member) => member.id === memberId ? { ...member, role: newRole } : member));
    try {
      const updated = await teamRequest<TeamMember>(`/teams/${memberId}/role`, apiKey, { method: "PATCH", body: JSON.stringify({ role: newRole }) });
      setMembers((current) => current.map((member) => member.id === memberId ? updated : member));
    } catch (err) {
      setMembers(previous);
      setError((err as Error).message);
    }
  };

  const removeMember = async (memberId: string) => {
    const previous = members;
    setMembers(members.filter((member) => member.id !== memberId));
    try {
      await teamRequest(`/teams/${memberId}`, apiKey, { method: "DELETE" });
    } catch (err) {
      setMembers(previous);
      setError((err as Error).message);
    }
  };

  const inviteMember = async (event: FormEvent) => {
    event.preventDefault();
    try {
      const member = await teamRequest<TeamMember>("/teams/invite", apiKey, { method: "POST", body: JSON.stringify({ name: inviteName, email: inviteEmail, role: inviteRole }) });
      setMembers((current) => [...current, member]);
      setInviteName(""); setInviteEmail(""); setInviteRole("viewer"); setInviteOpen(false); setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <div className="relative min-h-screen text-foreground">
      {/* Background glows */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] rounded-full" />

      {/* DESKTOP SIDEBAR (Reused from settings) */}
      <aside className="hidden md:flex w-72 h-screen fixed left-0 top-0 border-r border-border bg-card backdrop-blur-3xl flex-col z-20">
        <nav className="flex-1 px-4 py-30 space-y-2">
          <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 text-subtle hover:text-foreground hover:bg-surface rounded-2xl font-semibold transition">
            <span>📊</span> Dashboard
          </Link>
          <Link href="/settings" className="flex items-center gap-3 px-4 py-3 text-subtle hover:text-foreground hover:bg-surface rounded-2xl font-semibold transition">
            <span>⚙️</span> Profile Settings
          </Link>
          <Link href="/settings/teams" className="flex items-center gap-3 px-4 py-3 bg-surface border border-border rounded-2xl font-bold">
            <span className="text-indigo-400">👥</span> Team Management
          </Link>
        </nav>
      </aside>

      <main className="relative z-10 p-4 sm:p-6 md:p-12 md:ml-72">
        <header className="mb-10">
          <h1 className="text-3xl font-black tracking-tight mb-2">Team Management</h1>
          <p className="text-subtle font-medium">Manage members, roles, and workspace permissions.</p>
        </header>

        <nav className="flex gap-3 mb-8">
          <Link href="/settings" className="px-4 py-2 rounded-xl border border-border-strong text-sm font-semibold hover:bg-surface transition">
            General
          </Link>
          <Link href="/settings/teams" className="px-4 py-2 rounded-xl border border-border-strong bg-surface-strong text-sm font-semibold">
            Team
          </Link>
          <Link href="/settings/developer" className="px-4 py-2 rounded-xl border border-border-strong text-sm font-semibold hover:bg-surface transition">
            Developer
          </Link>
        </nav>

        <div className="rounded-3xl bg-card border border-border overflow-hidden">
          <div className="p-6 border-b border-border flex justify-between items-center">
            <h2 className="text-xl font-bold">Workspace Members</h2>
            <button
              onClick={() => setInviteOpen(true)}
              disabled={userRole !== "admin"}
              className={`px-4 py-2 bg-indigo-500 text-white text-sm font-bold rounded-xl transition ${userRole !== "admin" ? "opacity-50 cursor-not-allowed" : "hover:scale-105"}`}
            >
              + Invite Member
              {userRole !== "admin" && (
                <span className="block text-[10px] text-brand font-medium">Admin only</span>
              )}
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-subtle text-xs font-bold uppercase tracking-wider">
                  <th className="px-6 py-4">Member</th>
                  <th className="px-6 py-4">Role</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading && <tr><td className="px-6 py-8 text-subtle" colSpan={4}>Loading team members…</td></tr>}
                {!loading && error && <tr><td className="px-6 py-8 text-red-400" colSpan={4}>{error}</td></tr>}
                {!loading && !error && members.length === 0 && <tr><td className="px-6 py-8 text-subtle" colSpan={4}>No team members yet.</td></tr>}
                {!loading && members.map((member) => (
                  <tr key={member.id} className="group hover:bg-card/[0.02] transition">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-surface-strong rounded-full flex items-center justify-center font-bold text-indigo-400">
                          {member.name[0]}
                        </div>
                        <div>
                          <p className="font-bold">{member.name}</p>
                          <p className="text-xs text-subtle">{member.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <select 
                        value={member.role}
                        disabled={userRole !== "admin"}
                        onChange={(e) => handleRoleChange(member.id, e.target.value as "admin" | "operator" | "viewer")}
                        className="bg-card border border-border-strong rounded-lg px-2 py-1 text-sm outline-none focus:border-indigo-500 transition disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <option value="admin">Admin</option>
                        <option value="operator">Operator</option>
                        <option value="viewer">Viewer</option>
                      </select>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-1 rounded-md text-[10px] font-black uppercase tracking-widest ${
                        member.status === "active" ? "bg-success-soft text-emerald-500" : "bg-warning-soft text-amber-500"
                      }`}>
                        {member.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={() => removeMember(member.id)}
                        disabled={userRole !== "admin"}
                        className="p-2 text-subtle hover:text-red-500 transition disabled:opacity-0"
                      >
                        🗑️
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {inviteOpen && (
          <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/60 p-4">
            <form onSubmit={inviteMember} className="w-full max-w-md rounded-2xl bg-card border border-border p-6 space-y-4">
              <h2 className="text-xl font-bold">Invite team member</h2>
              <input required value={inviteName} onChange={(e) => setInviteName(e.target.value)} placeholder="Full name" className="w-full rounded-lg border border-border-strong bg-surface p-3" />
              <input required type="email" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="Email address" className="w-full rounded-lg border border-border-strong bg-surface p-3" />
              <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value as TeamRole)} className="w-full rounded-lg border border-border-strong bg-surface p-3">
                <option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option>
              </select>
              <div className="flex justify-end gap-3"><button type="button" onClick={() => setInviteOpen(false)} className="px-4 py-2">Cancel</button><button type="submit" className="px-4 py-2 rounded-xl bg-indigo-500 text-white font-bold">Send invite</button></div>
            </form>
          </div>
        )}

        {/* Role Descriptions */}
        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-2xl bg-surface border border-border">
            <p className="text-indigo-400 font-black text-xs uppercase mb-2">Admin</p>
            <p className="text-sm text-subtle">Full access to all settings, team management, and financial operations.</p>
          </div>
          <div className="p-6 rounded-2xl bg-surface border border-border">
            <p className="text-purple-400 font-black text-xs uppercase mb-2">Operator</p>
            <p className="text-sm text-subtle">Can manage links and view analytics, but cannot manage team or workspace settings.</p>
          </div>
          <div className="p-6 rounded-2xl bg-surface border border-border">
            <p className="text-subtle font-black text-xs uppercase mb-2">Viewer</p>
            <p className="text-sm text-subtle">Read-only access to dashboard and analytics. Cannot perform any actions.</p>
          </div>
        </div>
      </main>
    </div>
  );
}
