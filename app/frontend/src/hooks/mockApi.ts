export async function mockFetch<T>(response: T, delay = 1200): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve(response), delay);
  });
}