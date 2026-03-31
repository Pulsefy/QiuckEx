export async function mockFetch<T>(response: T, delay = 1200): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve(response), delay);
  });
}

export async function mockContractCall(action: "extend" | "cleanup", id: string): Promise<boolean> {
  console.log(`Mocking contract call: ${action} for ${id}`);
  return new Promise((resolve) => {
    setTimeout(() => resolve(true), 800);
  });
}