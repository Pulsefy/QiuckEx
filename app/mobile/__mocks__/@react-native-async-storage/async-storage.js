const store = {};

module.exports = {
  getItem: jest.fn(async (key) => store[key] ?? null),
  setItem: jest.fn(async (key, value) => { store[key] = value; }),
  removeItem: jest.fn(async (key) => { delete store[key]; }),
  clear: jest.fn(async () => { Object.keys(store).forEach((k) => delete store[k]); }),
};
