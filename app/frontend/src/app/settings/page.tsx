"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface ProfileForm {
  displayName: string;
  colour: string;
  avatar: string;
  bio: string;
  twitter: string;
  discord: string;
  github: string;
}

interface FormErrors {
  displayName?: string;
  colour?: string;
  avatar?: string;
  bio?: string;
  twitter?: string;
  discord?: string;
  github?: string;
}

export default function SettingsPage() {
  const router = useRouter();
  const [form, setForm] = useState<ProfileForm>({
    displayName: "",
    colour: "#3b82f6",
    avatar: "",
    bio: "",
    twitter: "",
    discord: "",
    github: "",
  });
  const [initialForm, setInitialForm] = useState<ProfileForm>(form);
  const [errors, setErrors] = useState<FormErrors>({});
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  const isDirty = JSON.stringify(form) !== JSON.stringify(initialForm);

  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isDirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [isDirty]);

  useEffect(() => {
    async function fetchProfile() {
      try {
        setLoading(true);
        setLoadError(null);
        const res = await fetch("/api/user/profile");
        if (!res.ok) throw new Error("Failed to load profile settings");
        const data = await res.json();
        const loadedData: ProfileForm = {
          displayName: data.displayName || "",
          colour: data.colour || "#3b82f6",
          avatar: data.avatar || "",
          bio: data.bio || "",
          twitter: data.twitter || "",
          discord: data.discord || "",
          github: data.github || "",
        };
        setForm(loadedData);
        setInitialForm(loadedData);
      } catch (err: any) {
        setLoadError(err.message || "Unexpected error occurred");
      } finally {
        setLoading(false);
      }
    }
    fetchProfile();
  }, []);

  const validate = (): boolean => {
    const newErrors: FormErrors = {};
    if (!form.displayName.trim()) {
      newErrors.displayName = "Display name is required";
    } else if (form.displayName.length > 50) {
      newErrors.displayName = "Display name cannot exceed 50 characters";
    }

    const hexRegex = /^#[0-9A-Fa-f]{6}$/;
    if (!hexRegex.test(form.colour)) {
      newErrors.colour = "Colour must be a valid hex code (e.g., #3b82f6)";
    }

    if (form.bio.length > 160) {
      newErrors.bio = "Bio cannot exceed 160 characters";
    }

    if (form.avatar && !/^https?:\/\/.+/.test(form.avatar)) {
      newErrors.avatar = "Avatar must be a valid URL";
    }

    if (form.twitter && form.twitter.length > 30) {
      newErrors.twitter = "Twitter handle is too long";
    }

    if (form.discord && form.discord.length > 30) {
      newErrors.discord = "Discord handle is too long";
    }

    if (form.github && form.github.length > 30) {
      newErrors.github = "GitHub handle is too long";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSuccessMessage(null);
    setApiError(null);

    if (!validate()) return;

    setSaving(true);
    try {
      const res = await fetch("/api/user/profile", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.message || "Failed to save profile settings");
      }

      setInitialForm(form);
      setSuccessMessage("Profile updated successfully!");
    } catch (err: any) {
      setApiError(err.message || "Failed to save profile settings");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div data-testid="loading-state" className="p-6">Loading profile settings...</div>;
  }

  if (loadError) {
    return (
      <div data-testid="error-state" className="p-6 text-red-500">
        Error: {loadError}
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Profile Settings</h1>
      {successMessage && <div data-testid="success-message" className="mb-4 p-3 bg-green-100 text-green-700 rounded">{successMessage}</div>}
      {apiError && <div data-testid="api-error" className="mb-4 p-3 bg-red-100 text-red-700 rounded">{apiError}</div>}
      
      <form onSubmit={handleSave} className="space-y-4">
        <div>
          <label className="block font-medium">Display Name</label>
          <input
            type="text"
            name="displayName"
            value={form.displayName}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.displayName && <p data-testid="error-displayName" className="text-red-500 text-sm">{errors.displayName}</p>}
        </div>

        <div>
          <label className="block font-medium">Colour</label>
          <input
            type="text"
            name="colour"
            value={form.colour}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.colour && <p data-testid="error-colour" className="text-red-500 text-sm">{errors.colour}</p>}
        </div>

        <div>
          <label className="block font-medium">Avatar URL</label>
          <input
            type="text"
            name="avatar"
            value={form.avatar}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.avatar && <p data-testid="error-avatar" className="text-red-500 text-sm">{errors.avatar}</p>}
        </div>

        <div>
          <label className="block font-medium">Bio</label>
          <textarea
            name="bio"
            value={form.bio}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.bio && <p data-testid="error-bio" className="text-red-500 text-sm">{errors.bio}</p>}
        </div>

        <div>
          <label className="block font-medium">Twitter</label>
          <input
            type="text"
            name="twitter"
            value={form.twitter}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.twitter && <p data-testid="error-twitter" className="text-red-500 text-sm">{errors.twitter}</p>}
        </div>

        <div>
          <label className="block font-medium">Discord</label>
          <input
            type="text"
            name="discord"
            value={form.discord}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.discord && <p data-testid="error-discord" className="text-red-500 text-sm">{errors.discord}</p>}
        </div>

        <div>
          <label className="block font-medium">GitHub</label>
          <input
            type="text"
            name="github"
            value={form.github}
            onChange={handleChange}
            className="w-full border p-2 rounded"
          />
          {errors.github && <p data-testid="error-github" className="text-red-500 text-sm">{errors.github}</p>}
        </div>

        <button
          type="submit"
          disabled={saving}
          className="bg-blue-600 text-white px-4 py-2 rounded disabled:opacity-50"
        >
          {saving ? "Saving..." : "Save"}
        </button>
      </form>
    </div>
  );
}
