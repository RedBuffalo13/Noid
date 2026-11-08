'use strict';

// deepmerge 4.3.1, MIT; see LICENSE and README.md for the security delta.
var canUseSymbol = typeof Symbol === 'function' && Symbol.for;
var REACT_ELEMENT_TYPE = canUseSymbol ? Symbol.for('react.element') : 0xeac7;

function defaultIsMergeableObject(value) {
	if (!value || typeof value !== 'object') {
		return false;
	}
	var stringValue = Object.prototype.toString.call(value);
	return stringValue !== '[object RegExp]'
		&& stringValue !== '[object Date]'
		&& value.$$typeof !== REACT_ELEMENT_TYPE;
}

function emptyTarget(val) {
	return Array.isArray(val) ? [] : {};
}

function cloneUnlessOtherwiseSpecified(value, options) {
	return (options.clone !== false && options.isMergeableObject(value))
		? deepmerge(emptyTarget(value), value, options)
		: value;
}

function defaultArrayMerge(target, source, options) {
	return target.concat(source).map(function(element) {
		return cloneUnlessOtherwiseSpecified(element, options);
	});
}

function getMergeFunction(key, options) {
	if (!options.customMerge) {
		return deepmerge;
	}
	var customMerge = options.customMerge(key);
	return typeof customMerge === 'function' ? customMerge : deepmerge;
}

function getEnumerableOwnPropertySymbols(target) {
	return Object.getOwnPropertySymbols
		? Object.getOwnPropertySymbols(target).filter(function(symbol) {
			return Object.propertyIsEnumerable.call(target, symbol);
		})
		: [];
}

function getKeys(target) {
	return Object.keys(target).concat(getEnumerableOwnPropertySymbols(target));
}

function propertyIsOnObject(object, property) {
	try {
		return property in object;
	} catch (_) {
		return false;
	}
}

function propertyIsUnsafe(target, key) {
	return propertyIsOnObject(target, key)
		&& !(Object.hasOwnProperty.call(target, key)
			&& Object.propertyIsEnumerable.call(target, key));
}

function setOwnProperty(destination, key, value) {
	// Assignment invokes Object.prototype.__proto__'s setter for hostile keys.
	// Define data properties for BOTH target copies and source writes instead.
	Object.defineProperty(destination, key, {
		value: value, enumerable: true, configurable: true, writable: true
	});
}

function mergeObject(target, source, options) {
	var destination = {};
	if (options.isMergeableObject(target)) {
		getKeys(target).forEach(function(key) {
			setOwnProperty(destination, key, cloneUnlessOtherwiseSpecified(target[key], options));
		});
	}
	getKeys(source).forEach(function(key) {
		if (propertyIsUnsafe(target, key)) {
			return;
		}
		if (propertyIsOnObject(target, key) && options.isMergeableObject(source[key])) {
			setOwnProperty(destination, key, getMergeFunction(key, options)(target[key], source[key], options));
		} else {
			setOwnProperty(destination, key, cloneUnlessOtherwiseSpecified(source[key], options));
		}
	});
	return destination;
}

function deepmerge(target, source, options) {
	options = options || {};
	options.arrayMerge = options.arrayMerge || defaultArrayMerge;
	options.isMergeableObject = options.isMergeableObject || defaultIsMergeableObject;
	options.cloneUnlessOtherwiseSpecified = cloneUnlessOtherwiseSpecified;
	var sourceIsArray = Array.isArray(source);
	var targetIsArray = Array.isArray(target);
	if (sourceIsArray !== targetIsArray) {
		return cloneUnlessOtherwiseSpecified(source, options);
	} else if (sourceIsArray) {
		return options.arrayMerge(target, source, options);
	}
	return mergeObject(target, source, options);
}

deepmerge.all = function deepmergeAll(array, options) {
	if (!Array.isArray(array)) {
		throw new Error('first argument should be an array');
	}
	return array.reduce(function(prev, next) {
		return deepmerge(prev, next, options);
	}, {});
};

module.exports = deepmerge;
