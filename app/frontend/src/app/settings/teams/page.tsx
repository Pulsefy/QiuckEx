"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { getQuickexApiBase } from "@/lib/api";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TeamRole = "owner" | "admin" | "member" | "viewer";

interface TeamMember {
  id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: TeamRole;
  joined_at: string;
  last_active_at: string | null;
  status: "active" | "pending";
  joinedAt: string;
  lastActiveAt: string | null;
}

interface Team {
  id: string;
  name: string;
  description?: string;
  ownerPublicKey: string;
  members: TeamMember[];
  createdAt: string;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function fetchTeams(publicKey: string): Promise<Team[]> {
  const res = await fetch(
    `${getQuickexApiBase()}/teams?ownerPublicKey=${encodeURIComponent(publicKey)}`,
  );
  if (!res.ok) throw new Error(`Failed to load teams (${res.status})`);
  const data = (await res.json()) as { teams: Team[] };
  return data.teams;
}

async function createTeam(
  publicKey: string,
  name: string,
): Promise<Team> {
  const res = await fetch(
    `${getQuickexApiBase()}/teams?ownerPublicKey=${encodeURIComponent(publicKey)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    },
  );
  if (!res.ok) throw new Error(`Failed to create team (${res.status})`);
  return res.json() as Promise<Team>;
}

async function inviteMember(
  teamId: string,
  actorPublicKey: string,
  email: string,
  role: Exclude<TeamRole, "owner">,
): Promise<TeamMember> {
  const res = await fetch(
    `${getQuickexApiBase()}/teams/${teamId}/members?actorPublicKey=${encodeURIComponent(actorPublicKey)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, role }),
    },
  );
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error((err as { message?: string }).message ?? `Invite failed (${res.status})`);
  }
  return res.json() as Promise<TeamMember>;
}

async function removeMember(
  teamId: string,
  memberId: string,
  actorPublicKey: string,
): Promise<void> {
  const res = await fetch(
    `${getQuickexApiBase()}/teams/${teamId}/members/${memberId}?actorPublicKey=${encodeURIComponent(actorPublicKey)}`,
    { method: "DELETE" },
  );
  if (!res.ok) throw new Error(`Remove member failed (${res.status})`);
}

async function updateMemberRole(
  teamId: string,
  memberId: string,
  role: Exclude<TeamRole, "owner">,
  actorPublicKey: string,
): Promise<TeamMember> {
  const res = await fetch(
    `${getQuickexApiBase()}/teams/${teamId}/members/${memberId}/role?actorPublicKey=${encodeURIComponent(actorPublicKey)}`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    },
  );
  if (!res.ok) throw new Error(`Role update failed (${res.status})`);
  return res.json() as Promise<TeamMember>;
}

async function generateInviteLink(
  teamId: string,
  actorPublicKey: string,
): Promise<{ inviteUrl: string; expiresAt: string }> {
  const res = await fetch(
    `${getQuickexApiBase()}/teams/${teamId}/invite-link?actorPublicKey=${encodeURIComponent(actorPublicKey)}`,
    { method: "POST" },
  );
  if (!res.ok) throw new Error(`Invite link generation failed (${res.status})`);
  return res.json() as Promise<{ inviteUrl: string; expiresAt: string }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string | null): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function roleLabel(role: TeamRole): string {
  return role.charAt(0).toUpperCase() + role.slice(1);
}

function roleBadgeClass(role: TeamRole): string {
  switch (role) {
    case "owner":   return "bg-indigo-500/10 text-indigo-400 border-indigo-500/20";
    case "admin":   return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    case "member":  return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    default:        return "bg-slate-500/10 text-slate-400 border-slate-500/20";
  }
}

interface TeamInfo {
  id: string;
  name: string;
  owner_id: string;
  member_count: number;
  created_at: string;
}

interface InviteLink {
  id: string;
  team_id: string;
  invite_url: string;
  role: TeamRole;
  expires_at: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getQuickexApiBase()}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.message ?? `Request failed: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return "—";
  }
}

function formatTimeAgo(iso: string | null | undefined): string {
  if (!iso) return "Never";
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  } catch {
    return "—";
  }
}

const ROLE_COLORS: Record<TeamRole, string> = {
  owner: "text-indigo-400",
  admin: "text-purple-400",
  member: "text-emerald-400",
  viewer: "text-slate-400",
};

const ROLES_ASSIGNABLE: TeamRole[] = ["admin", "member", "viewer"];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function TeamSettings() {
  const [team, setTeam] = useState<TeamInfo | null>(null);
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Invite modal state
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteName, setInviteName] = useState("");
  const [inviteRole, setInviteRole] = useState<TeamRole>("member");
  const [inviting, setInviting] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);

  // Invite link state
  const [inviteLink, setInviteLink] = useState<InviteLink | null>(null);
  const [generatingLink, setGeneratingLink] = useState(false);
  const [inviteLinkRole, setInviteLinkRole] = useState<TeamRole>("member");
  const [linkCopied, setLinkCopied] = useState(false);

  // Create team modal state
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [newTeamName, setNewTeamName] = useState("");
  const [creatingTeam, setCreatingTeam] = useState(false);

  // Current user — in production this comes from auth context
  const currentUserId = "current-user-id";

  const currentMember = members.find((m) => m.user_id === currentUserId);
  const currentRole: TeamRole = currentMember?.role ?? "viewer";
  const isOwner = currentRole === "owner";
  const isAdmin = currentRole === "admin" || isOwner;

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  const loadTeamData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Try to load from a known team id stored in localStorage
      const storedTeamId =
        typeof window !== "undefined"
          ? window.localStorage.getItem("quickex.teamId")
          : null;

      if (!storedTeamId) {
        setLoading(false);
        return;
      }

      const [teamData, membersData] = await Promise.all([
        apiFetch<TeamInfo>(`/teams/${storedTeamId}`),
        apiFetch<TeamMember[]>(`/teams/${storedTeamId}/members`),
      ]);
      setTeam(teamData);
      setMembers(membersData);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTeamData();
  }, [loadTeamData]);

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  const handleCreateTeam = async () => {
    if (!newTeamName.trim()) return;
    setCreatingTeam(true);
    try {
      const created = await apiFetch<TeamInfo>("/teams", {
        method: "POST",
        body: JSON.stringify({ name: newTeamName.trim() }),
      });
      if (typeof window !== "undefined") {
        window.localStorage.setItem("quickex.teamId", created.id);
      }
      setTeam(created);
      setMembers([]);
      setShowCreateTeam(false);
      setNewTeamName("");
      await loadTeamData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setCreatingTeam(false);
    }
  };

  const handleInviteMember = async () => {
    if (!team || !inviteEmail.trim()) return;
    setInviting(true);
    setInviteError(null);
    try {
      const member = await apiFetch<TeamMember>(`/teams/${team.id}/members`, {
        method: "POST",
        body: JSON.stringify({
          email: inviteEmail.trim(),
          name: inviteName.trim() || undefined,
          role: inviteRole,
        }),
      });
      setMembers((prev) => [...prev, member]);
      setShowInvite(false);
      setInviteEmail("");
      setInviteName("");
      setInviteRole("member");
    } catch (err) {
      setInviteError((err as Error).message);
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (member: TeamMember, newRole: TeamRole) => {
    if (!team || !isAdmin) return;
    if (newRole === "owner") return; // use transfer ownership
    try {
      const updated = await apiFetch<TeamMember>(
        `/teams/${team.id}/members/${member.id}/role`,
        {
          method: "PUT",
          body: JSON.stringify({ role: newRole }),
        },
      );
      setMembers((prev) => prev.map((m) => (m.id === updated.id ? updated : m)));
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleRemoveMember = async (member: TeamMember) => {
    if (!team || !isOwner) return;
    if (!window.confirm(`Remove ${member.email} from the team?`)) return;
    try {
      await apiFetch(`/teams/${team.id}/members/${member.id}`, {
        method: "DELETE",
      });
      setMembers((prev) => prev.filter((m) => m.id !== member.id));
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleGenerateInviteLink = async () => {
    if (!team) return;
    setGeneratingLink(true);
    try {
      const link = await apiFetch<InviteLink>(`/teams/${team.id}/invite-link`, {
        method: "POST",
        body: JSON.stringify({ role: inviteLinkRole }),
      });
      setInviteLink(link);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setGeneratingLink(false);
    }
  };

  const handleCopyLink = async () => {
    if (!inviteLink) return;
    try {
      await navigator.clipboard.writeText(inviteLink.invite_url);
      setLinkCopied(true);
      setTimeout(() => setLinkCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  // ---------------------------------------------------------------------------
  // Render helpers
  // ---------------------------------------------------------------------------

  const RoleBadge = ({ role }: { role: TeamRole }) => (
    <span
      className={`px-2 py-0.5 rounded-md text-[10px] font-black uppercase tracking-widest border border-current/20 ${ROLE_COLORS[role]}`}
    >
      {role}
    </span>
  );

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="relative min-h-screen text-foreground">
      {/* Background glow */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] rounded-full" />

      {/* Sidebar */}
      <aside className="hidden md:flex w-72 h-screen fixed left-0 top-0 border-r border-border bg-card backdrop-blur-3xl flex-col z-20">
        <nav className="flex-1 px-4 py-30 space-y-2">
          <Link
            href="/dashboard"
            className="flex items-center gap-3 px-4 py-3 text-subtle hover:text-foreground hover:bg-surface rounded-2xl font-semibold transition"
          >
            <span>📊</span> Dashboard
          </Link>
          <Link
            href="/settings"
            className="flex items-center gap-3 px-4 py-3 text-subtle hover:text-foreground hover:bg-surface rounded-2xl font-semibold transition"
          >
            <span>⚙️</span> Profile Settings
          </Link>
          <Link
            href="/settings/teams"
            className="flex items-center gap-3 px-4 py-3 bg-surface border border-border rounded-2xl font-bold"
          >
            <span className="text-indigo-400">👥</span> Team Management
          </Link>
          <Link
            href="/settings/developer"
            className="flex items-center gap-3 px-4 py-3 text-subtle hover:text-foreground hover:bg-surface rounded-2xl font-semibold transition"
          >
            <span>🔑</span> Developer
          </Link>
        </nav>
      </aside>

      <main className="relative z-10 p-4 sm:p-6 md:p-12 md:ml-72">
        {/* Page header */}
        <header className="mb-10">
          <h1 className="text-3xl font-black tracking-tight mb-2">
            Team Management
          </h1>
          <p className="text-subtle font-medium">
            Manage members, roles, and workspace permissions.
          </p>
        </header>

        {/* Sub-nav */}
        <nav className="flex gap-3 mb-8">
          <Link
            href="/settings"
            className="px-4 py-2 rounded-xl border border-border-strong text-sm font-semibold hover:bg-surface transition"
          >
            General
          </Link>
          <Link
            href="/settings/teams"
            className="px-4 py-2 rounded-xl border border-border-strong bg-surface-strong text-sm font-semibold"
          >
            Team
          </Link>
          <Link
            href="/settings/developer"
            className="px-4 py-2 rounded-xl border border-border-strong text-sm font-semibold hover:bg-surface transition"
          >
            Developer
          </Link>
        </nav>

        {/* Error banner */}
        {error && (
          <div className="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm font-medium flex items-center justify-between">
            <span>{error}</span>
            <button
              onClick={() => setError(null)}
              className="ml-4 text-red-400 hover:text-red-300 transition"
              aria-label="Dismiss error"
            >
              ✕
            </button>
          </div>
        )}

        {/* No team yet */}
        {!loading && !team && (
          <div className="rounded-3xl bg-card border border-border p-12 text-center">
            <div className="text-5xl mb-4">👥</div>
            <h2 className="text-xl font-bold mb-2">No Team Yet</h2>
            <p className="text-subtle text-sm mb-6">
              Create a team workspace to collaborate with others.
            </p>
            <button
              onClick={() => setShowCreateTeam(true)}
              className="px-6 py-3 bg-indigo-500 text-white text-sm font-bold rounded-xl hover:bg-indigo-400 transition"
            >
              + Create Team
            </button>
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="rounded-3xl bg-card border border-border p-12 text-center">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-subtle text-sm">Loading team data…</p>
          </div>
        )}

        {/* Team content */}
        {!loading && team && (
          <>
            {/* Team info header */}
            <div className="mb-6 p-6 rounded-2xl bg-card border border-border flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-xl font-black text-indigo-400">
                  {team.name[0]?.toUpperCase()}
                </div>
                <div>
                  <h2 className="text-lg font-black">{team.name}</h2>
                  <p className="text-xs text-subtle">
                    {team.member_count} member{team.member_count !== 1 ? "s" : ""} · Created{" "}
                    {formatDate(team.created_at)}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <RoleBadge role={currentRole} />
              </div>
            </div>

            {/* Members table */}
            <div className="rounded-3xl bg-card border border-border overflow-hidden mb-8">
              <div className="p-6 border-b border-border flex justify-between items-center flex-wrap gap-3">
                <h2 className="text-xl font-bold">Workspace Members</h2>
                {isAdmin && (
                  <button
                    onClick={() => setShowInvite(true)}
                    className="px-4 py-2 bg-indigo-500 text-white text-sm font-bold rounded-xl hover:bg-indigo-400 transition"
                  >
                    + Invite Member
                  </button>
                )}
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="text-subtle text-xs font-bold uppercase tracking-wider border-b border-border">
                      <th className="px-6 py-4">Member</th>
                      <th className="px-6 py-4">Role</th>
                      <th className="px-6 py-4">Joined</th>
                      <th className="px-6 py-4">Last Active</th>
                      <th className="px-6 py-4">Status</th>
                      {isOwner && (
                        <th className="px-6 py-4 text-right">Actions</th>
                      )}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {members.map((member) => {
                      const isSelf = member.user_id === currentUserId;
                      const isOwnerMember = member.role === "owner";
                      const canChangeRole =
                        isAdmin && !isSelf && !isOwnerMember;
                      const canRemove = isOwner && !isSelf && !isOwnerMember;

                      return (
                        <tr
                          key={member.id}
                          className="hover:bg-white/[0.02] transition"
                        >
                          <td className="px-6 py-4">
                            <div className="flex items-center gap-3">
                              <div className="w-10 h-10 bg-surface-strong rounded-full flex items-center justify-center font-bold text-indigo-400 shrink-0">
                                {(member.name ?? member.email)[0]?.toUpperCase()}
                              </div>
                              <div>
                                <p className="font-bold">
                                  {member.name ?? "—"}
                                  {isSelf && (
                                    <span className="ml-2 text-[10px] text-indigo-400 font-black">
                                      (you)
                                    </span>
                                  )}
                                </p>
                                <p className="text-xs text-subtle">{member.email}</p>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            {canChangeRole ? (
                              <select
                                value={member.role}
                                onChange={(e) =>
                                  handleRoleChange(member, e.target.value as TeamRole)
                                }
                                className="bg-card border border-border-strong rounded-lg px-2 py-1 text-sm outline-none focus:border-indigo-500 transition"
                              >
                                {ROLES_ASSIGNABLE.map((r) => (
                                  <option key={r} value={r}>
                                    {r.charAt(0).toUpperCase() + r.slice(1)}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              <RoleBadge role={member.role} />
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm text-subtle">
                            {formatDate(member.joined_at)}
                          </td>
                          <td className="px-6 py-4 text-sm text-subtle">
                            {formatTimeAgo(member.last_active_at)}
                          </td>
                          <td className="px-6 py-4">
                            <span
                              className={`px-2 py-1 rounded-md text-[10px] font-black uppercase tracking-widest ${
                                member.status === "active"
                                  ? "bg-emerald-500/10 text-emerald-400"
                                  : "bg-amber-500/10 text-amber-400"
                              }`}
                            >
                              {member.status}
                            </span>
                          </td>
                          {isOwner && (
                            <td className="px-6 py-4 text-right">
                              <button
                                onClick={() => handleRemoveMember(member)}
                                disabled={!canRemove}
                                className="p-2 text-subtle hover:text-red-400 transition disabled:opacity-20 disabled:cursor-not-allowed"
                                title={canRemove ? "Remove member" : undefined}
                                aria-label={`Remove ${member.email}`}
                              >
                                🗑️
                              </button>
                            </td>
                          )}
                        </tr>
                      );
                    })}
                    {members.length === 0 && (
                      <tr>
                        <td
                          colSpan={isOwner ? 6 : 5}
                          className="px-6 py-12 text-center text-subtle text-sm"
                        >
                          No members yet. Invite someone to get started.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Invite link section */}
            {isAdmin && (
              <div className="rounded-3xl bg-card border border-border p-6 mb-8">
                <h3 className="text-lg font-bold mb-1">Invite Link</h3>
                <p className="text-sm text-subtle mb-4">
                  Generate a shareable link valid for 7 days. Anyone with the link joins with
                  the selected role.
                </p>
                <div className="flex flex-wrap items-center gap-3">
                  <select
                    value={inviteLinkRole}
                    onChange={(e) => setInviteLinkRole(e.target.value as TeamRole)}
                    className="bg-card border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                  >
                    {ROLES_ASSIGNABLE.map((r) => (
                      <option key={r} value={r}>
                        {r.charAt(0).toUpperCase() + r.slice(1)}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={handleGenerateInviteLink}
                    disabled={generatingLink}
                    className="px-4 py-2 bg-indigo-500 text-white text-sm font-bold rounded-xl hover:bg-indigo-400 transition disabled:opacity-50"
                  >
                    {generatingLink ? "Generating…" : "Generate Link"}
                  </button>
                </div>
                {inviteLink && (
                  <div className="mt-4 p-4 rounded-2xl bg-surface border border-border flex flex-col sm:flex-row items-start sm:items-center gap-3">
                    <code className="text-xs text-indigo-300 break-all flex-1">
                      {inviteLink.invite_url}
                    </code>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-xs text-subtle">
                        Expires {formatDate(inviteLink.expires_at)}
                      </span>
                      <button
                        onClick={handleCopyLink}
                        className="px-3 py-1.5 bg-indigo-500/20 text-indigo-300 text-xs font-bold rounded-lg hover:bg-indigo-500/30 transition"
                      >
                        {linkCopied ? "✓ Copied" : "Copy"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Role descriptions */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {(
                [
                  {
                    role: "owner" as TeamRole,
                    color: "text-indigo-400",
                    desc: "Full control — can delete the team, transfer ownership, and manage all members.",
                  },
                  {
                    role: "admin" as TeamRole,
                    color: "text-purple-400",
                    desc: "Can invite/remove members and change roles (except owner).",
                  },
                  {
                    role: "member" as TeamRole,
                    color: "text-emerald-400",
                    desc: "Can manage links and view analytics, but cannot manage team settings.",
                  },
                  {
                    role: "viewer" as TeamRole,
                    color: "text-slate-400",
                    desc: "Read-only access to dashboard and analytics. Cannot perform any actions.",
                  },
                ] as const
              ).map(({ role, color, desc }) => (
                <div
                  key={role}
                  className="p-5 rounded-2xl bg-surface border border-border"
                >
                  <p className={`${color} font-black text-xs uppercase tracking-widest mb-2`}>
                    {role}
                  </p>
                  <p className="text-sm text-subtle">{desc}</p>
                </div>
              ))}
            </div>
          </>
        )}
      </main>

      {/* ------------------------------------------------------------------- */}
      {/* Invite member modal                                                  */}
      {/* ------------------------------------------------------------------- */}
      {showInvite && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-card border border-border rounded-3xl p-8 shadow-2xl">
            <h3 className="text-xl font-black mb-1">Invite Member</h3>
            <p className="text-subtle text-sm mb-6">
              Send an invitation to a new team member.
            </p>

            {inviteError && (
              <p className="mb-4 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-xl p-3">
                {inviteError}
              </p>
            )}

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Email *
                </label>
                <input
                  type="email"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="colleague@example.com"
                  className="w-full bg-surface border border-border-strong rounded-xl px-4 py-3 text-sm outline-none focus:border-indigo-500 transition"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Name (optional)
                </label>
                <input
                  type="text"
                  value={inviteName}
                  onChange={(e) => setInviteName(e.target.value)}
                  placeholder="Alice"
                  className="w-full bg-surface border border-border-strong rounded-xl px-4 py-3 text-sm outline-none focus:border-indigo-500 transition"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Role *
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as TeamRole)}
                  className="w-full bg-surface border border-border-strong rounded-xl px-4 py-3 text-sm outline-none focus:border-indigo-500 transition"
                >
                  {ROLES_ASSIGNABLE.map((r) => (
                    <option key={r} value={r}>
                      {r.charAt(0).toUpperCase() + r.slice(1)}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="mt-6 flex gap-3">
              <button
                onClick={() => {
                  setShowInvite(false);
                  setInviteError(null);
                  setInviteEmail("");
                  setInviteName("");
                  setInviteRole("member");
                }}
                className="flex-1 px-4 py-3 border border-border-strong rounded-xl text-sm font-bold hover:bg-surface transition"
              >
                Cancel
              </button>
              <button
                onClick={handleInviteMember}
                disabled={inviting || !inviteEmail.trim()}
                className="flex-1 px-4 py-3 bg-indigo-500 text-white rounded-xl text-sm font-bold hover:bg-indigo-400 transition disabled:opacity-50"
              >
                {inviting ? "Inviting…" : "Send Invite"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------- */}
      {/* Create team modal                                                    */}
      {/* ------------------------------------------------------------------- */}
      {showCreateTeam && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-card border border-border rounded-3xl p-8 shadow-2xl">
            <h3 className="text-xl font-black mb-1">Create Team</h3>
            <p className="text-subtle text-sm mb-6">
              Start a new workspace for your team.
            </p>
            <div>
              <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                Team Name *
              </label>
              <input
                type="text"
                value={newTeamName}
                onChange={(e) => setNewTeamName(e.target.value)}
                placeholder="Engineering"
                maxLength={64}
                className="w-full bg-surface border border-border-strong rounded-xl px-4 py-3 text-sm outline-none focus:border-indigo-500 transition"
              />
            </div>
            <div className="mt-6 flex gap-3">
              <button
                onClick={() => {
                  setShowCreateTeam(false);
                  setNewTeamName("");
                }}
                className="flex-1 px-4 py-3 border border-border-strong rounded-xl text-sm font-bold hover:bg-surface transition"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateTeam}
                disabled={creatingTeam || !newTeamName.trim()}
                className="flex-1 px-4 py-3 bg-indigo-500 text-white rounded-xl text-sm font-bold hover:bg-indigo-400 transition disabled:opacity-50"
              >
                {creatingTeam ? "Creating…" : "Create Team"}
              </button>
            </div>
          </div>
        ) : selectedTeam ? (
          <>
            {/* Member list */}
            <div className="rounded-3xl bg-card border border-border overflow-hidden mb-8">
              <div className="p-6 border-b border-border flex flex-wrap justify-between items-center gap-4">
                <div>
                  <h2 className="text-xl font-bold">{selectedTeam.name}</h2>
                  {selectedTeam.description && (
                    <p className="text-subtle text-sm mt-1">{selectedTeam.description}</p>
                  )}
                </div>
                <div className="flex gap-3">
                  {canManage && (
                    <button
                      onClick={() => void handleGenerateInviteLink()}
                      className="px-4 py-2 border border-border-strong text-sm font-semibold rounded-xl hover:bg-surface transition"
                    >
                      🔗 Invite Link
                    </button>
                  )}
                </div>
              </div>

              {/* Invite link banner */}
              {inviteLink && (
                <div className="px-6 py-4 bg-indigo-500/5 border-b border-border flex flex-col sm:flex-row gap-3 items-start sm:items-center">
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-subtle mb-1">Invite link (expires {formatDate(inviteLinkExpiry)})</p>
                    <code className="text-xs text-indigo-400 break-all">{inviteLink}</code>
                  </div>
                  <button
                    onClick={() => void navigator.clipboard.writeText(inviteLink ?? "").then(() => showToast("Copied!"))}
                    className="px-3 py-1.5 text-xs font-semibold bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded-lg hover:bg-indigo-500/20 transition shrink-0"
                  >
                    Copy
                  </button>
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <thead>
                    <tr className="text-subtle text-xs font-bold uppercase tracking-wider border-b border-border">
                      <th className="px-6 py-4">Member</th>
                      <th className="px-6 py-4">Role</th>
                      <th className="px-6 py-4">Joined</th>
                      <th className="px-6 py-4">Last Active</th>
                      <th className="px-6 py-4">Status</th>
                      <th className="px-6 py-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {selectedTeam.members.map((member) => (
                      <tr key={member.id} className="hover:bg-card/[0.02] transition">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-9 h-9 bg-surface-strong rounded-full flex items-center justify-center font-bold text-indigo-400 text-sm shrink-0">
                              {member.email[0]?.toUpperCase()}
                            </div>
                            <p className="text-sm font-semibold truncate max-w-[200px]">{member.email}</p>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          {canManage && member.role !== "owner" ? (
                            <select
                              value={member.role}
                              onChange={(e) =>
                                void handleRoleChange(
                                  member,
                                  e.target.value as Exclude<TeamRole, "owner">,
                                )
                              }
                              className="bg-card border border-border-strong rounded-lg px-2 py-1 text-sm outline-none focus:border-indigo-500 transition"
                            >
                              <option value="admin">Admin</option>
                              <option value="member">Member</option>
                              <option value="viewer">Viewer</option>
                            </select>
                          ) : (
                            <span
                              className={`px-2.5 py-1 rounded-lg text-xs font-bold border ${roleBadgeClass(member.role)}`}
                            >
                              {roleLabel(member.role)}
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-sm text-subtle">
                          {formatDate(member.joinedAt)}
                        </td>
                        <td className="px-6 py-4 text-sm text-subtle">
                          {formatDate(member.lastActiveAt)}
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`px-2 py-1 rounded-md text-[10px] font-black uppercase tracking-widest ${
                              member.status === "active"
                                ? "bg-emerald-500/10 text-emerald-500"
                                : "bg-amber-500/10 text-amber-500"
                            }`}
                          >
                            {member.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          {canManage && member.role !== "owner" && (
                            <button
                              onClick={() => void handleRemoveMember(member)}
                              className="p-2 text-subtle hover:text-red-400 transition"
                              title="Remove member"
                            >
                              🗑️
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Invite form */}
            {canManage && (
              <div className="rounded-3xl bg-card border border-border p-6 mb-8">
                <h2 className="text-lg font-bold mb-4">Invite a member</h2>
                <div className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    placeholder="Email address"
                    className="flex-1 bg-surface border border-border-strong rounded-xl px-4 py-2 text-sm outline-none focus:border-indigo-500 transition"
                  />
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value as Exclude<TeamRole, "owner">)}
                    className="bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                  >
                    <option value="admin">Admin</option>
                    <option value="member">Member</option>
                    <option value="viewer">Viewer</option>
                  </select>
                  <button
                    onClick={() => void handleInvite()}
                    disabled={inviting || !inviteEmail.trim()}
                    className="px-5 py-2 bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-sm font-bold rounded-xl transition"
                  >
                    {inviting ? "Sending…" : "Invite"}
                  </button>
                </div>
              </div>
            )}
          </>
        ) : null}

        {/* Role descriptions */}
        <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            { color: "text-indigo-400",  label: "Owner",  desc: "Full access. Can delete or transfer the team." },
            { color: "text-purple-400",  label: "Admin",  desc: "Manage members and invite links. Cannot delete the team." },
            { color: "text-emerald-400", label: "Member", desc: "Manage links and view analytics. Cannot change team settings." },
            { color: "text-slate-400",   label: "Viewer", desc: "Read-only access to dashboard and analytics." },
          ].map(({ color, label, desc }) => (
            <div key={label} className="p-5 rounded-2xl bg-surface border border-border">
              <p className={`${color} font-black text-xs uppercase mb-2`}>{label}</p>
              <p className="text-sm text-subtle">{desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
