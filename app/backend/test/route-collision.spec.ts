import * as fs from 'fs';
import * as path from 'path';
import * as glob from 'glob';

describe("Route Configuration (Static Analysis)", () => {
  it("should not have duplicate controller prefixes", () => {
    // Find all controller files in the src directory
    const srcDir = path.resolve(__dirname, '../src');
    const controllerFiles = glob.sync('**/*.controller.ts', { cwd: srcDir });

    const prefixes = new Map<string, string[]>();

    for (const file of controllerFiles) {
      const fullPath = path.join(srcDir, file);
      const content = fs.readFileSync(fullPath, 'utf-8');

      // Match @Controller('prefix') or @Controller("prefix")
      // this matches string literals. Arrays like @Controller(['a', 'b']) will be ignored.
      const match = content.match(/@Controller\(\s*(['"`])(.*?)\1\s*\)/);
      if (match) {
        const prefix = match[2];
        const normalizedPrefix = prefix === '' ? '/' : prefix;

        // Ignore root controllers or empty prefixes
        if (normalizedPrefix !== '/') {
          const current = prefixes.get(normalizedPrefix) || [];
          if (!current.includes(file)) {
            current.push(file);
          }
          prefixes.set(normalizedPrefix, current);
        }
      } else if (content.match(/@Controller\(\s*\)/)) {
        // empty @Controller() is treated as '/'
        // ignored
      }
    }

    const duplicates = Array.from(prefixes.entries()).filter(([_, files]) => files.length > 1);
    
    // We expect no duplicates. If there are, print them out clearly in the error.
    expect(duplicates).toEqual([]);
  });
});
