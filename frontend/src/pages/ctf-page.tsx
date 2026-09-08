import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BookOpenText,
  Check,
  Eye,
  EyeOff,
  Flag,
  Pencil,
  Plus,
  Radar,
  Trash2,
  X,
} from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";

import {
  createChallenge,
  deleteChallenge,
  getChallenges,
  updateChallenge,
} from "../api/ctf";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import type {
  CtfChallenge,
  CtfChallengeCreate,
  CtfChallengeStatus,
} from "../types/resources";

const fieldClass =
  "h-9 w-full rounded-md border border-line bg-black/20 px-3 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-cyan-400/50";

const CATEGORIES = ["web", "crypto", "pwn", "reverse", "forensics", "misc", "osint", "hardware"];
const DIFFICULTIES = ["", "easy", "medium", "hard", "insane"];
const STATUS_ORDER: CtfChallengeStatus[] = ["todo", "in_progress", "solved"];
const STATUS_LABEL: Record<CtfChallengeStatus, string> = {
  todo: "To do",
  in_progress: "In progress",
  solved: "Solved",
};

function statusTone(status: CtfChallengeStatus): "safe" | "warning" | "neutral" {
  if (status === "solved") return "safe";
  if (status === "in_progress") return "warning";
  return "neutral";
}

function nextStatus(status: CtfChallengeStatus): CtfChallengeStatus {
  return STATUS_ORDER[(STATUS_ORDER.indexOf(status) + 1) % STATUS_ORDER.length] ?? "todo";
}

type FormState = CtfChallengeCreate;

const EMPTY_FORM: FormState = {
  name: "",
  event: "",
  category: "web",
  difficulty: "",
  points: null,
  target_url: "",
  notes: "",
  flag: "",
};

export function CtfPage() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());

  const challenges = useQuery({
    queryKey: ["ctf-challenges"],
    queryFn: ({ signal }) => getChallenges(undefined, signal),
  });

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["ctf-challenges"] });

  const create = useMutation({
    mutationFn: createChallenge,
    onSuccess: async () => {
      await invalidate();
      resetForm();
      toast.success("Challenge added");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const update = useMutation({
    mutationFn: ({ id, input }: { id: string; input: Partial<CtfChallengeCreate> }) =>
      updateChallenge(id, input),
    onSuccess: async () => {
      await invalidate();
      resetForm();
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const remove = useMutation({
    mutationFn: deleteChallenge,
    onSuccess: async () => {
      await invalidate();
      toast.success("Challenge removed");
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const items = useMemo(() => challenges.data ?? [], [challenges.data]);
  const grouped = useMemo(() => {
    const map = new Map<string, CtfChallenge[]>();
    for (const item of items) {
      const key = item.event || "Ungrouped";
      const bucket = map.get(key) ?? [];
      bucket.push(item);
      map.set(key, bucket);
    }
    return [...map.entries()];
  }, [items]);
  const counts = useMemo(() => {
    const base = { todo: 0, in_progress: 0, solved: 0 } as Record<CtfChallengeStatus, number>;
    for (const item of items) base[item.status] += 1;
    return base;
  }, [items]);

  const resetForm = () => {
    setForm(EMPTY_FORM);
    setEditingId(null);
    setShowForm(false);
  };

  const startEdit = (challenge: CtfChallenge) => {
    setEditingId(challenge.id);
    setForm({
      name: challenge.name,
      event: challenge.event,
      category: challenge.category,
      difficulty: challenge.difficulty,
      points: challenge.points,
      target_url: challenge.target_url,
      notes: challenge.notes,
      flag: challenge.flag,
    });
    setShowForm(true);
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!form.name.trim()) return;
    if (editingId) {
      update.mutate({ id: editingId, input: form });
    } else {
      create.mutate(form);
    }
  };

  const toggleReveal = (id: string) => {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="mx-auto max-w-[1200px] space-y-6 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-cyan-300">
            <BookOpenText className="size-4" /> CTF Workspace
          </p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-100">Challenge tracker</h1>
          <p className="mt-1 text-sm text-slate-500">
            Organize challenges, notes, and flags by event. Launch a scan against any
            challenge that has a target URL.
          </p>
        </div>
        <Button
          onClick={() => {
            if (showForm && !editingId) resetForm();
            else {
              setForm(EMPTY_FORM);
              setEditingId(null);
              setShowForm(true);
            }
          }}
        >
          <Plus className="size-4" /> New challenge
        </Button>
      </header>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {(["todo", "in_progress", "solved"] as const).map((status) => (
          <Card key={status}>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-widest text-slate-500">
                {STATUS_LABEL[status]}
              </CardTitle>
            </CardHeader>
            <CardContent className="flex items-center gap-2 text-2xl font-semibold text-slate-100">
              {counts[status]}
              <Badge tone={statusTone(status)}>{status}</Badge>
            </CardContent>
          </Card>
        ))}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-widest text-slate-500">Total</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-semibold text-slate-100">{items.length}</CardContent>
        </Card>
      </div>

      {showForm ? (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm text-slate-200">
              {editingId ? "Edit challenge" : "New challenge"}
            </CardTitle>
            <button
              type="button"
              aria-label="Close form"
              className="text-slate-500 hover:text-slate-200"
              onClick={resetForm}
            >
              <X className="size-4" />
            </button>
          </CardHeader>
          <CardContent>
            <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
              <label className="text-xs text-slate-400">
                Name
                <input
                  aria-label="Name"
                  required
                  className={`${fieldClass} mt-1`}
                  value={form.name}
                  onChange={(event) => setForm({ ...form, name: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-400">
                Event
                <input
                  aria-label="Event"
                  className={`${fieldClass} mt-1`}
                  placeholder="e.g. PicoCTF 2025"
                  value={form.event}
                  onChange={(event) => setForm({ ...form, event: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-400">
                Category
                <select
                  aria-label="Category"
                  className={`${fieldClass} mt-1`}
                  value={form.category}
                  onChange={(event) => setForm({ ...form, category: event.target.value })}
                >
                  {CATEGORIES.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
              </label>
              <div className="grid grid-cols-2 gap-3">
                <label className="text-xs text-slate-400">
                  Difficulty
                  <select
                    aria-label="Difficulty"
                    className={`${fieldClass} mt-1`}
                    value={form.difficulty}
                    onChange={(event) => setForm({ ...form, difficulty: event.target.value })}
                  >
                    {DIFFICULTIES.map((difficulty) => (
                      <option key={difficulty} value={difficulty}>
                        {difficulty || "—"}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="text-xs text-slate-400">
                  Points
                  <input
                    aria-label="Points"
                    type="number"
                    min={0}
                    className={`${fieldClass} mt-1`}
                    value={form.points ?? ""}
                    onChange={(event) =>
                      setForm({
                        ...form,
                        points: event.target.value === "" ? null : Number(event.target.value),
                      })
                    }
                  />
                </label>
              </div>
              <label className="text-xs text-slate-400 sm:col-span-2">
                Target URL
                <input
                  aria-label="Target URL"
                  className={`${fieldClass} mt-1`}
                  placeholder="https://ctf.example/challenge"
                  value={form.target_url}
                  onChange={(event) => setForm({ ...form, target_url: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-400 sm:col-span-2">
                Notes
                <textarea
                  aria-label="Notes"
                  className="mt-1 min-h-20 w-full resize-y rounded-md border border-line bg-black/20 p-3 text-sm text-slate-100 outline-none focus:border-cyan-400/50"
                  value={form.notes}
                  onChange={(event) => setForm({ ...form, notes: event.target.value })}
                />
              </label>
              <label className="text-xs text-slate-400 sm:col-span-2">
                Flag
                <input
                  aria-label="Flag"
                  className={`${fieldClass} mt-1 font-mono`}
                  placeholder="flag{...}"
                  value={form.flag}
                  onChange={(event) => setForm({ ...form, flag: event.target.value })}
                />
              </label>
              <div className="flex items-center gap-2 sm:col-span-2">
                <Button type="submit" disabled={create.isPending || update.isPending}>
                  <Check className="size-4" /> {editingId ? "Save" : "Add challenge"}
                </Button>
                <Button type="button" variant="ghost" onClick={resetForm}>
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}

      {challenges.isLoading ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-slate-500">Loading challenges…</CardContent>
        </Card>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-slate-500">
            No challenges tracked yet. Add one to get started.
          </CardContent>
        </Card>
      ) : (
        grouped.map(([event, group]) => (
          <Card key={event}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm text-slate-200">
                {event}
                <Badge tone="neutral">{group.length}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {group.map((challenge) => (
                <div
                  key={challenge.id}
                  className="rounded-lg border border-line bg-black/15 p-3"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      aria-label={`Cycle status for ${challenge.name}`}
                      onClick={() =>
                        update.mutate({
                          id: challenge.id,
                          input: { status: nextStatus(challenge.status) },
                        })
                      }
                    >
                      <Badge tone={statusTone(challenge.status)}>
                        {STATUS_LABEL[challenge.status]}
                      </Badge>
                    </button>
                    <span className="text-sm font-medium text-slate-100">{challenge.name}</span>
                    {challenge.category ? <Badge tone="accent">{challenge.category}</Badge> : null}
                    {challenge.difficulty ? (
                      <span className="text-[11px] text-slate-500">{challenge.difficulty}</span>
                    ) : null}
                    {challenge.points !== null ? (
                      <span className="text-[11px] text-slate-500">{challenge.points} pts</span>
                    ) : null}
                    <div className="ml-auto flex items-center gap-1">
                      {challenge.target_url ? (
                        <Link
                          to={`/scans?target=${encodeURIComponent(challenge.target_url)}&profile=ctf`}
                          title="Scan this target"
                          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-cyan-300 hover:bg-white/[0.05]"
                        >
                          <Radar className="size-3.5" /> Scan
                        </Link>
                      ) : null}
                      <button
                        type="button"
                        aria-label={`Edit ${challenge.name}`}
                        className="rounded-md p-1 text-slate-500 hover:bg-white/5 hover:text-slate-200"
                        onClick={() => startEdit(challenge)}
                      >
                        <Pencil className="size-3.5" />
                      </button>
                      <button
                        type="button"
                        aria-label={`Delete ${challenge.name}`}
                        className="rounded-md p-1 text-slate-500 hover:bg-red-500/10 hover:text-red-300"
                        onClick={() => remove.mutate(challenge.id)}
                      >
                        <Trash2 className="size-3.5" />
                      </button>
                    </div>
                  </div>
                  {challenge.notes ? (
                    <p className="mt-2 whitespace-pre-wrap text-xs text-slate-400">{challenge.notes}</p>
                  ) : null}
                  {challenge.flag ? (
                    <div className="mt-2 flex items-center gap-2">
                      <Flag className="size-3.5 text-emerald-300" />
                      <code className="font-mono text-xs text-emerald-200">
                        {revealed.has(challenge.id) ? challenge.flag : "•".repeat(12)}
                      </code>
                      <button
                        type="button"
                        aria-label={
                          revealed.has(challenge.id) ? "Hide flag" : "Reveal flag"
                        }
                        className="text-slate-500 hover:text-slate-300"
                        onClick={() => toggleReveal(challenge.id)}
                      >
                        {revealed.has(challenge.id) ? (
                          <EyeOff className="size-3.5" />
                        ) : (
                          <Eye className="size-3.5" />
                        )}
                      </button>
                    </div>
                  ) : null}
                </div>
              ))}
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}
