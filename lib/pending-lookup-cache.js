class PendingLookupCache {
    constructor(logger) {
        if (logger) {
            this.log = logger;
        } else {
            this.log = {
                info: console.info,
                debug: console.debug,
                trace: console.trace,
                warn: console.warn,
                error: console.error
            };
        }

        this.pendingLookups = new Map();
        this.runningLookups = new Set();
        this.enabled = false;

        this.stats = {
            pendingLookupsExecuted: 0,
            pendingLookupsAdded: 0
        }
    }

    isEnabled() {
        return this.enabled;
    }

    setEnabled(enabled) {
        this.enabled = enabled;
    }

    isRunning(key) {
        if (this.enabled) {
            return this.runningLookups.has(key.toLowerCase());
        } else {
            return false;
        }
    }

    addRunningLookup(key) {
        if (this.enabled) {
            this.log.debug({key:key}, 'Add Running Lookup');
            this.runningLookups.add(key.toLowerCase());
        }
    }

    removeRunningLookup(key) {
        if (this.enabled) {
            this.log.debug({key:key}, 'Remove Running Lookup');
            this.runningLookups.delete(key.toLowerCase());
        }
    }

    addPendingLookup(key, callback) {
        if (this.enabled) {
            let keyLower = key.toLowerCase();
            if (this.pendingLookups.has(keyLower)) {
                this.pendingLookups.get(keyLower).push(callback);
            } else {
                this.pendingLookups.set(keyLower, [callback]);
            }
            this.stats.pendingLookupsAdded++;
        }
    }

    executePendingLookups(resultObject) {
        if (this.enabled) {
            let keyLower = resultObject.entity.value.toLowerCase();
            let callbacks = this.pendingLookups.get(keyLower);
            if (Array.isArray(callbacks)) {
                callbacks.forEach(callback => {
                    this.stats.pendingLookupsExecuted++;
                    callback(null, [resultObject]);
                });
                this.pendingLookups.delete(keyLower);
            }
        }
    }

    reset(){
        if(this.enabled){
            this.pendingLookups.clear();
            this.runningLookups.clear();
        }
    }

    logStats(){
        this.log.debug({
            pendingLookupsExecuted: this.stats.pendingLookupsExecuted,
            pendingLookupsAdded: this.stats.pendingLookupsAdded,
            numPendingLookups: this.pendingLookups.size,
            numRunningLookups: this.runningLookups.size
        }, 'pending-lookup-cache stats')
    }
}

module.exports = PendingLookupCache;