const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createRequire } = require('node:module');
const merge = require('./index.cjs');

test('npm consumers select the patched implementation', () => {
	const consumerRequire = createRequire(require.resolve('@sveltejs/vite-plugin-svelte'));
	assert.equal(consumerRequire('deepmerge'), merge);
});

test('target own __proto__ cannot change the result prototype', () => {
	const merged = merge(JSON.parse('{"__proto__":{"poisoned":true}}'), {});
	assert.equal(Object.getPrototypeOf(merged), Object.prototype);
	assert.equal(merged.poisoned, undefined);
	assert.equal({}.poisoned, undefined);
	assert.deepEqual(Object.getOwnPropertyDescriptor(merged, '__proto__').value, { poisoned: true });
});

test('null-prototype target cannot expose inherited setter through source', () => {
	const merged = merge(Object.create(null), JSON.parse('{"__proto__":{"poisoned":true}}'));
	assert.equal(Object.getPrototypeOf(merged), Object.prototype);
	assert.equal(merged.poisoned, undefined);
});

test('nested target prototype poisoning is blocked recursively', () => {
	const merged = merge(JSON.parse('{"nested":{"__proto__":{"poisoned":true}}}'), {});
	assert.equal(Object.getPrototypeOf(merged.nested), Object.prototype);
	assert.equal(merged.nested.poisoned, undefined);
});

test('clone, arrays, enumerable symbols and nonmergeable objects are retained', () => {
	const symbol = Symbol('option');
	const date = new Date(0);
	const regexp = /test/;
	const target = { nested: { a: 1 }, items: [{ x: 1 }], date, regexp, [symbol]: { a: 1 } };
	const merged = merge(target, { nested: { b: 2 }, items: [2], [symbol]: { b: 2 } });
	assert.deepEqual(merged.nested, { a: 1, b: 2 });
	assert.deepEqual(merged.items, [{ x: 1 }, 2]);
	assert.notEqual(merged.items[0], target.items[0]);
	assert.equal(merged.date, date);
	assert.equal(merged.regexp, regexp);
	assert.deepEqual(merged[symbol], { a: 1, b: 2 });
});

test('vite-plugin-svelte array replacement and custom merge preserve API', () => {
	assert.deepEqual(merge({ list: [1] }, { list: [2] }, {
		arrayMerge: (target, source) => source ?? target
	}), { list: [2] });
	assert.deepEqual(merge({ item: { a: 1 } }, { item: { b: 2 } }, {
		customMerge: (key) => key === 'item' ? () => 'custom' : undefined
	}), { item: 'custom' });
});

test('all, clone false, invalid input and inherited-key guards match upstream', () => {
	assert.deepEqual(merge.all([{ a: 1 }, { b: 2 }]), { a: 1, b: 2 });
	const nested = { x: 1 };
	assert.equal(merge({}, { nested }, { clone: false }).nested, nested);
	assert.throws(() => merge.all({}), /array/);
	const inherited = Object.create({ notOwn: true });
	assert.deepEqual(merge({}, inherited), {});
	assert.deepEqual(merge({}, JSON.parse('{"__proto__":{"poisoned":true}}')), {});
});
