/**
 * Data parsing and transformation utilities for JMH benchmark results
 */

import type {
  JmhBenchmarkResult,
  JmhMode,
  ParsedBenchmark,
  BenchmarkComparison,
  BenchmarkCategory,
  Provider,
  HierarchyNode,
} from '../types/benchmark';

/**
 * Parse benchmark name into category, algorithm, and operation
 */
function parseBenchmarkName(benchmark: string): {
  category: BenchmarkCategory;
  algorithm: string;
  operation: string;
} {
  // Format: com.benchmark.{Category}Benchmark.{Algorithm}.{operation}
  const parts = benchmark.split('.');
  const categoryPart = parts[2]; // e.g., "KdfBenchmark", "PqcBenchmark", "SymmetricBenchmark"
  const algorithm = parts[3]; // e.g., "Pbkdf2", "MlDsa", "Aes"
  const operation = parts[4]; // e.g., "deriveKey", "keyGen", "encrypt"

  let category: BenchmarkCategory;
  if (categoryPart.includes('Pqc')) {
    category = 'PQC';
  } else if (categoryPart.includes('Kdf')) {
    category = 'KDF';
  } else {
    category = 'Symmetric';
  }

  return { category, algorithm, operation };
}

/**
 * Extract variant (key size, algorithm variant) from benchmark params
 */
function extractVariant(params: Record<string, string>, category: BenchmarkCategory): string {
  if (category === 'Symmetric') {
    const keySize = params.keySize || '';
    return keySize ? `${keySize}-bit` : 'default';
  }

  if (category === 'PQC') {
    return params.algorithm || 'default';
  }

  return 'default';
}

/**
 * Extract mode (cipher mode/padding for symmetric) from params - for backward compatibility
 */
function extractMode(params: Record<string, string>, category: BenchmarkCategory): string | null {
  if (category === 'Symmetric' && params.transform) {
    const parts = params.transform.split('/');
    if (parts.length >= 3) {
      return `${parts[1]}/${parts[2]}`;
    }
    return parts.slice(1).join('/');
  }
  return null;
}

/**
 * Extract cipher mode (CBC, CFB, CTR, etc.) for symmetric ciphers
 */
function extractCipherMode(params: Record<string, string>, category: BenchmarkCategory): string | null {
  if (category === 'Symmetric' && params.transform) {
    const parts = params.transform.split('/');
    if (parts.length >= 2) {
      return parts[1]; // e.g., "CBC", "CFB128", "CTR"
    }
  }
  return null;
}

/**
 * Extract padding mode for symmetric ciphers
 */
function extractPadding(params: Record<string, string>, category: BenchmarkCategory): string | null {
  if (category === 'Symmetric' && params.transform) {
    const parts = params.transform.split('/');
    if (parts.length >= 3) {
      return parts[2]; // e.g., "NoPadding", "PKCS5Padding"
    }
  }
  return null;
}

/**
 * Extract hash algorithm for KDF (PBKDF2)
 */
function extractHashAlgorithm(params: Record<string, string>, algorithm: string): string | null {
  if (algorithm === 'Pbkdf2' && params.algorithm) {
    // params.algorithm format: PBKDF2WithHmacSHA256 or PBKDF2WithHmacSHA3-256
    const match = params.algorithm.match(/PBKDF2WithHmac(.+)/);
    if (match) {
      return match[1]; // e.g., "SHA256", "SHA3-256", "SM3"
    }
    return params.algorithm;
  }
  return null;
}

/**
 * Extract iterations/parameter for KDF
 */
function extractIterations(params: Record<string, string>, algorithm: string): string | null {
  if (algorithm === 'Pbkdf2' && params.iterations) {
    return `${params.iterations} iterations`;
  }
  if (algorithm === 'Scrypt' && params.N) {
    return `N=${params.N}`;
  }
  return null;
}

/**
 * Parse a single JMH result into a structured format
 */
export function parseBenchmark(result: JmhBenchmarkResult): ParsedBenchmark {
  const { category, algorithm, operation } = parseBenchmarkName(result.benchmark);
  const variant = extractVariant(result.params, category);
  const mode = extractMode(result.params, category);
  const cipherMode = extractCipherMode(result.params, category);
  const padding = extractPadding(result.params, category);
  const hashAlgorithm = extractHashAlgorithm(result.params, algorithm);
  const iterations = extractIterations(result.params, algorithm);
  const provider = result.params.providerName as Provider;

  const id = `${category}-${algorithm}-${operation}-${variant}-${cipherMode || 'default'}-${padding || 'default'}-${hashAlgorithm || 'default'}-${iterations || 'default'}-${result.mode}-${provider}`;

  return {
    id,
    category,
    algorithm,
    operation,
    variant,
    mode,
    cipherMode,
    padding,
    hashAlgorithm,
    iterations,
    jmhMode: result.mode,
    provider,
    score: result.primaryMetric.score,
    scoreError: result.primaryMetric.scoreError,
    scoreUnit: result.primaryMetric.scoreUnit,
    rawData: result,
  };
}

/**
 * Create comparison key for matching BC and Jostle benchmarks
 */
function getComparisonKey(b: ParsedBenchmark): string {
  return `${b.category}-${b.algorithm}-${b.operation}-${b.variant}-${b.cipherMode || 'default'}-${b.padding || 'default'}-${b.hashAlgorithm || 'default'}-${b.iterations || 'default'}-${b.jmhMode}`;
}

/**
 * Group parsed benchmarks into comparisons (BC vs Jostle pairs)
 */
export function createComparisons(benchmarks: ParsedBenchmark[]): BenchmarkComparison[] {
  const groupedByKey = new Map<string, { bc?: ParsedBenchmark; jostle?: ParsedBenchmark }>();

  for (const b of benchmarks) {
    const key = getComparisonKey(b);
    if (!groupedByKey.has(key)) {
      groupedByKey.set(key, {});
    }
    const group = groupedByKey.get(key)!;
    if (b.provider === 'BC') {
      group.bc = b;
    } else {
      group.jostle = b;
    }
  }

  const comparisons: BenchmarkComparison[] = [];

  for (const [key, group] of groupedByKey) {
    const reference = group.bc || group.jostle!;
    comparisons.push({
      id: key,
      category: reference.category,
      algorithm: reference.algorithm,
      operation: reference.operation,
      variant: reference.variant,
      mode: reference.mode,
      cipherMode: reference.cipherMode,
      padding: reference.padding,
      hashAlgorithm: reference.hashAlgorithm,
      iterations: reference.iterations,
      jmhMode: reference.jmhMode,
      bcScore: group.bc?.score ?? null,
      bcError: group.bc?.scoreError ?? null,
      jostleScore: group.jostle?.score ?? null,
      jostleError: group.jostle?.scoreError ?? null,
      scoreUnit: reference.scoreUnit,
      bcRaw: group.bc?.rawData ?? null,
      jostleRaw: group.jostle?.rawData ?? null,
    });
  }

  return comparisons;
}

/**
 * Build hierarchy for Symmetric benchmarks
 * Structure: Algorithm > Operation > KeySize > CipherMode > Padding
 */
function buildSymmetricHierarchy(
  comparisons: BenchmarkComparison[],
  basePath: string
): HierarchyNode[] {
  const nodes: HierarchyNode[] = [];

  // Group by algorithm
  const byAlgorithm = groupBy(comparisons, (c) => c.algorithm);

  for (const [algorithm, algoComparisons] of byAlgorithm) {
    const algoNode: HierarchyNode = {
      name: algorithm,
      path: `${basePath}/${algorithm}`,
      children: [],
      comparisons: algoComparisons,
    };

    // Group by operation (encrypt, decrypt)
    const byOperation = groupBy(algoComparisons, (c) => c.operation);

    for (const [operation, opComparisons] of byOperation) {
      const opNode: HierarchyNode = {
        name: operation,
        path: `${basePath}/${algorithm}/${operation}`,
        children: [],
        comparisons: opComparisons,
      };

      // Group by key size
      const byKeySize = groupBy(opComparisons, (c) => c.variant);

      for (const [keySize, keySizeComparisons] of byKeySize) {
        const keySizeNode: HierarchyNode = {
          name: keySize,
          path: `${basePath}/${algorithm}/${operation}/${encodeURIComponent(keySize)}`,
          children: [],
          comparisons: keySizeComparisons,
        };

        // Group by cipher mode (CBC, CFB, CTR, etc.)
        const byCipherMode = groupBy(keySizeComparisons, (c) => c.cipherMode || 'default');

        for (const [cipherMode, modeComparisons] of byCipherMode) {
          const modeNode: HierarchyNode = {
            name: cipherMode,
            path: `${basePath}/${algorithm}/${operation}/${encodeURIComponent(keySize)}/${encodeURIComponent(cipherMode)}`,
            children: [],
            comparisons: modeComparisons,
          };

          // Group by padding
          const byPadding = groupBy(modeComparisons, (c) => c.padding || 'default');

          if (byPadding.size > 1) {
            for (const [padding, paddingComparisons] of byPadding) {
              const paddingNode: HierarchyNode = {
                name: padding,
                path: `${basePath}/${algorithm}/${operation}/${encodeURIComponent(keySize)}/${encodeURIComponent(cipherMode)}/${encodeURIComponent(padding)}`,
                children: [],
                comparisons: paddingComparisons,
              };
              modeNode.children.push(paddingNode);
            }
          }

          keySizeNode.children.push(modeNode);
        }

        opNode.children.push(keySizeNode);
      }

      algoNode.children.push(opNode);
    }

    nodes.push(algoNode);
  }

  return nodes;
}

/**
 * Build hierarchy for KDF benchmarks
 * Structure: Algorithm > HashAlgorithm/Parameter > Iterations
 */
function buildKdfHierarchy(
  comparisons: BenchmarkComparison[],
  basePath: string
): HierarchyNode[] {
  const nodes: HierarchyNode[] = [];

  // Group by algorithm (Pbkdf2, Scrypt)
  const byAlgorithm = groupBy(comparisons, (c) => c.algorithm);

  for (const [algorithm, algoComparisons] of byAlgorithm) {
    const algoNode: HierarchyNode = {
      name: algorithm,
      path: `${basePath}/${algorithm}`,
      children: [],
      comparisons: algoComparisons,
    };

    if (algorithm === 'Pbkdf2') {
      // For PBKDF2: HashAlgorithm > Iterations
      const byHash = groupBy(algoComparisons, (c) => c.hashAlgorithm || 'default');

      for (const [hash, hashComparisons] of byHash) {
        const hashNode: HierarchyNode = {
          name: hash,
          path: `${basePath}/${algorithm}/${encodeURIComponent(hash)}`,
          children: [],
          comparisons: hashComparisons,
        };

        // Group by iterations
        const byIterations = groupBy(hashComparisons, (c) => c.iterations || 'default');

        for (const [iterations, iterComparisons] of byIterations) {
          const iterNode: HierarchyNode = {
            name: iterations,
            path: `${basePath}/${algorithm}/${encodeURIComponent(hash)}/${encodeURIComponent(iterations)}`,
            children: [],
            comparisons: iterComparisons,
          };
          hashNode.children.push(iterNode);
        }

        algoNode.children.push(hashNode);
      }
    } else {
      // For Scrypt: just N parameter
      const byN = groupBy(algoComparisons, (c) => c.iterations || 'default');

      for (const [n, nComparisons] of byN) {
        const nNode: HierarchyNode = {
          name: n,
          path: `${basePath}/${algorithm}/${encodeURIComponent(n)}`,
          children: [],
          comparisons: nComparisons,
        };
        algoNode.children.push(nNode);
      }
    }

    nodes.push(algoNode);
  }

  return nodes;
}

/**
 * Build hierarchy for PQC benchmarks
 * Structure: Algorithm > Operation > Variant
 */
function buildPqcHierarchy(
  comparisons: BenchmarkComparison[],
  basePath: string
): HierarchyNode[] {
  const nodes: HierarchyNode[] = [];

  // Group by algorithm
  const byAlgorithm = groupBy(comparisons, (c) => c.algorithm);

  for (const [algorithm, algoComparisons] of byAlgorithm) {
    const algoNode: HierarchyNode = {
      name: algorithm,
      path: `${basePath}/${algorithm}`,
      children: [],
      comparisons: algoComparisons,
    };

    // Group by operation
    const byOperation = groupBy(algoComparisons, (c) => c.operation);

    for (const [operation, opComparisons] of byOperation) {
      const opNode: HierarchyNode = {
        name: operation,
        path: `${basePath}/${algorithm}/${operation}`,
        children: [],
        comparisons: opComparisons,
      };

      // Group by variant
      const byVariant = groupBy(opComparisons, (c) => c.variant);

      for (const [variant, varComparisons] of byVariant) {
        const varNode: HierarchyNode = {
          name: variant,
          path: `${basePath}/${algorithm}/${operation}/${encodeURIComponent(variant)}`,
          children: [],
          comparisons: varComparisons,
        };
        opNode.children.push(varNode);
      }

      algoNode.children.push(opNode);
    }

    nodes.push(algoNode);
  }

  return nodes;
}

/**
 * Helper function to group items by a key
 */
function groupBy<T>(items: T[], keyFn: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(item);
  }
  return groups;
}

/**
 * Build hierarchical navigation structure from comparisons
 */
export function buildHierarchy(comparisons: BenchmarkComparison[]): HierarchyNode {
  const root: HierarchyNode = {
    name: 'All Benchmarks',
    path: '',
    children: [],
    comparisons: comparisons,
  };

  // Group by category
  const byCategory = groupBy(comparisons, (c) => c.category);

  for (const [category, categoryComparisons] of byCategory) {
    const categoryNode: HierarchyNode = {
      name: category,
      path: category,
      children: [],
      comparisons: categoryComparisons,
    };

    // Build category-specific hierarchy
    if (category === 'Symmetric') {
      categoryNode.children = buildSymmetricHierarchy(categoryComparisons, category);
    } else if (category === 'KDF') {
      categoryNode.children = buildKdfHierarchy(categoryComparisons, category);
    } else if (category === 'PQC') {
      categoryNode.children = buildPqcHierarchy(categoryComparisons, category);
    }

    root.children.push(categoryNode);
  }

  // Sort children at each level
  sortHierarchy(root);

  return root;
}

function sortHierarchy(node: HierarchyNode): void {
  node.children.sort((a, b) => a.name.localeCompare(b.name));
  for (const child of node.children) {
    sortHierarchy(child);
  }
}

/**
 * Load and parse all benchmark data
 */
export async function loadBenchmarkData(): Promise<{
  raw: JmhBenchmarkResult[];
  parsed: ParsedBenchmark[];
  comparisons: BenchmarkComparison[];
  hierarchy: HierarchyNode;
}> {
  const response = await fetch(`${import.meta.env.BASE_URL}results.json`);
  const raw: JmhBenchmarkResult[] = await response.json();

  const parsed = raw.map(parseBenchmark);
  const comparisons = createComparisons(parsed);
  const hierarchy = buildHierarchy(comparisons);

  return { raw, parsed, comparisons, hierarchy };
}

/**
 * Filter comparisons by JMH mode
 */
export function filterByJmhMode(
  comparisons: BenchmarkComparison[],
  mode: JmhMode
): BenchmarkComparison[] {
  return comparisons.filter((c) => c.jmhMode === mode);
}

/**
 * Get all unique JMH modes from comparisons
 */
export function getUniqueJmhModes(comparisons: BenchmarkComparison[]): JmhMode[] {
  const modes = new Set<JmhMode>();
  for (const c of comparisons) {
    modes.add(c.jmhMode);
  }
  return Array.from(modes).sort();
}
