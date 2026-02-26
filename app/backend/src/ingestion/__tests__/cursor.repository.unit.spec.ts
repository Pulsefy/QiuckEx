import { CursorRepository } from "../cursor.repository";
import { SupabaseService } from "../../supabase/supabase.service";

function makeSupabaseMock(getData: unknown, error: unknown = null) {
  const maybeSingle = jest.fn().mockResolvedValue({ data: getData, error });
  const eq = jest.fn().mockReturnValue({ maybeSingle });
  const select = jest.fn().mockReturnValue({ eq });

  const upsertResult = jest.fn().mockResolvedValue({ error: null });

  const from = jest.fn().mockImplementation((table: string) => {
    if (table === "cursors") {
      return { select, upsert: upsertResult };
    }
    return {};
  });

  return {
    getClient: () => ({ from }),
    _upsertResult: upsertResult,
    _eq: eq,
  };
}

describe("CursorRepository", () => {
  it("returns null when no cursor row exists", async () => {
    const supabase = makeSupabaseMock(null) as unknown as SupabaseService;
    const repo = new CursorRepository(supabase);

    const result = await repo.getCursor("contract:CTEST");
    expect(result).toBeNull();
  });

  it("returns the stored paging_token", async () => {
    const supabase = makeSupabaseMock({
      paging_token: "99-5",
    }) as unknown as SupabaseService;
    const repo = new CursorRepository(supabase);

    const result = await repo.getCursor("contract:CTEST");
    expect(result).toBe("99-5");
  });

  it("upserts the cursor on save", async () => {
    const mock = makeSupabaseMock(null);
    const repo = new CursorRepository(mock as unknown as SupabaseService);

    await repo.saveCursor("contract:CTEST", "101-2", 101);

    expect(mock._upsertResult).toHaveBeenCalled();
  });

  it("throws when Supabase returns an error on getCursor", async () => {
    const supabase = makeSupabaseMock(null, {
      message: "DB error",
    }) as unknown as SupabaseService;
    const repo = new CursorRepository(supabase);

    await expect(repo.getCursor("contract:CTEST")).rejects.toMatchObject({
      message: "DB error",
    });
  });
});
