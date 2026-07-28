"use client";

import { useEffect } from "react";
import { useParams, useRouter } from "next/navigation";

export default function MarketplaceListingDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();

  useEffect(() => {
    const listingId = typeof params.id === "string" ? params.id : "";
    if (!listingId) {
      router.replace("/marketplace");
      return;
    }
    router.replace(`/marketplace?listing=${encodeURIComponent(listingId)}`);
  }, [params.id, router]);

  return (
    <div className="flex min-h-[40vh] items-center justify-center text-sm text-subtle">
      Opening listing detail…
    </div>
  );
}
