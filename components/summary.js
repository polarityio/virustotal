/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

'use strict';
polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  baselineInvestigationThreshold: Ember.computed(
    'block.data.details.positives',
    function () {
      const rules = this.get('details.compiledBaselineInvestigationRules');


      const positives = this.get('details.positives');
      for (let i = 0; i < rules.length; i++) {
        let rule = rules[i];
        if (positives >= rule.min && positives <= rule.max) {
          return {
            message: rule.message,
            level: rule.level
          };
        }
      }
      return null;
    }
  )
});
