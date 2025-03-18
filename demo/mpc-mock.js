/**
 * Mock Secure Multi-Party Computation (SMPC) Library
 * 
 * This is a simplified mock implementation for demonstration purposes only.
 * In a real-world scenario, secure multi-party computation would be implemented using
 * established cryptographic libraries such as MP-SPDZ, SCALE-MAMBA, or Sharemind,
 * which provide the necessary protocols and primitives for privacy-preserving computation.
 * Here, data is processed in plaintext for simplicity, but real SMPC would operate on
 * secret-shared values to ensure no individual node learns the underlying data.
 */

// ----- Node Implementation -----

/**
 * Represents a computation node in the SMPC network.
 * Each node holds shares of data, performs local computations, and maintains logs.
 */
class Node {
  /**
   * Creates a new SMPC node.
   * @param {string} id - Unique identifier for the node.
   */
  constructor(id) {
    this.id = id;
    this.shares = [];         // Holds data shares received by the node
    this.computedShares = []; // Holds results of local computations
    this.logs = [];           // Holds log messages for debugging and tracking
  }

  /**
   * Adds a data share to this node.
   * In real SMPC, shares would be secret-shared (e.g., split into random values summing to the original).
   * @param {Object} share - Data share to add, e.g., { glucose: 120, medication: "insulin" }.
   */
  addDataShare(share) {
    this.shares.push(share);
    this.log(`Received data share ${this.shares.length}`);
  }

  /**
   * Performs a local computation on the node's data shares based on the specified operation.
   * @param {string} operation - The operation to perform (e.g., "sum", "average", "filter", "aggregate").
   * @param {Object} params - Parameters specific to the operation.
   * @returns {Object|Object[]} - Result of the computation.
   */
  compute(operation, params) {
    this.log(`Computing operation: ${operation}`);
    
    switch (operation) {
      case "sum":
        return this.computeSum();
      case "average":
        return this.computeAverage();
      case "filter":
        return this.filterShares(params);
      case "aggregate":
        return this.aggregateByField(params.field);
      default:
        throw new Error(`Unknown operation: ${operation}`);
    }
  }

  /**
   * Computes the sum of numeric values across all shares.
   * In real SMPC, this would operate on secret shares, and the sum would be reconstructed securely.
   * @returns {Object} - An object with summed values for each key, e.g., { glucose: 360 }.
   */
  computeSum() {
    const result = {};
    
    this.shares.forEach(share => {
      Object.entries(share).forEach(([key, value]) => {
        if (typeof value === "number") {
          result[key] = (result[key] || 0) + value;
        } else if (typeof value === "string" && value.match(/^\d+$/)) {
          result[key] = (result[key] || 0) + parseInt(value, 10);
        }
      });
    });
    
    this.computedShares.push(result);
    return result;
  }

  /**
   * Computes the average of numeric values across all shares.
   * In real SMPC, this would require a secure division protocol across nodes.
   * @returns {Object} - An object with average values for each key, e.g., { glucose: 120 }.
   */
  computeAverage() {
    const sums = this.computeSum();
    const result = {};
    
    Object.entries(sums).forEach(([key, value]) => {
      if (typeof value === "number") {
        result[key] = value / this.shares.length;
      }
    });
    
    this.computedShares.push(result);
    return result;
  }

  /**
   * Filters shares based on provided criteria.
   * In real SMPC, filtering would be performed without revealing which shares match the criteria.
   * @param {Object} criteria - Filter criteria, e.g., { timeRange: "2023" }.
   * @returns {Object[]} - Array of shares matching the criteria.
   */
  filterShares(criteria) {
    const filtered = this.shares.filter(share => {
      return Object.entries(criteria).every(([field, value]) => share[field] === value);
    });
    
    this.log(`Filtered ${filtered.length} shares out of ${this.shares.length}`);
    return filtered;
  }

  /**
   * Aggregates shares by a specified field and computes averages for numeric values in each group.
   * In real SMPC, aggregation would be done securely without revealing individual data points.
   * @param {string} field - The field to aggregate by, e.g., "medication".
   * @returns {Object} - Aggregated results, e.g., { insulin: { count: 2, values: { glucose: 125 } } }.
   */
  aggregateByField(field) {
    const aggregation = {};
    
    this.shares.forEach(share => {
      const key = share[field];
      if (!key) return; // Skip if the field is missing
      
      if (!aggregation[key]) {
        aggregation[key] = { count: 0, values: {} };
      }
      
      aggregation[key].count++;
      
      Object.entries(share).forEach(([k, v]) => {
        if (k !== field && typeof v === "number") {
          aggregation[key].values[k] = (aggregation[key].values[k] || 0) + v;
        }
      });
    });
    
    // Compute averages for each group
    Object.values(aggregation).forEach(group => {
      Object.entries(group.values).forEach(([k, v]) => {
        group.values[k] = v / group.count;
      });
    });
    
    this.computedShares.push(aggregation);
    return aggregation;
  }

  /**
   * Logs a message for debugging or tracking purposes.
   * @param {string} message - The message to log.
   */
  log(message) {
    this.logs.push(`[Node ${this.id}] ${message}`);
  }
}

// ----- Protocol Implementation -----

/**
 * Represents an SMPC computation protocol that coordinates computation across multiple nodes.
 */
class Protocol {
  /**
   * Creates a new SMPC protocol instance.
   * @param {Node[]} nodes - Array of nodes participating in the computation.
   * @param {string} algorithm - The algorithm to execute, e.g., "average-glucose-by-medication".
   */
  constructor(nodes, algorithm) {
    this.nodes = nodes;
    this.algorithm = algorithm;
    this.logs = []; // Holds protocol-level log messages
  }

  /**
   * Executes the SMPC protocol based on the algorithm and parameters.
   * @param {Object} parameters - Parameters for the algorithm, e.g., { timeRange: "2023" }.
   * @returns {Promise<Object>} - The final computation result.
   */
  async execute(parameters) {
    this.log(`Executing protocol with algorithm: ${this.algorithm}`);
    
    // Step 1: Create a computation plan based on the algorithm
    const computationPlan = this.createComputationPlan(parameters);
    
    // Step 2: Execute each step of the plan across all nodes
    let intermediateResults = [];
    for (const step of computationPlan) {
      this.log(`Executing step: ${step.operation}`);
      
      const nodeResults = await Promise.all(
        this.nodes.map(node => node.compute(step.operation, step.parameters))
      );
      
      intermediateResults.push(nodeResults);
    }
    
    // Step 3: Combine results from all nodes into a final result
    const finalResult = this.combineResults(intermediateResults, computationPlan);
    
    return finalResult;
  }

  /**
   * Creates a computation plan based on the algorithm.
   * Each step defines an operation and its parameters.
   * @param {Object} parameters - Algorithm-specific parameters.
   * @returns {Object[]} - Array of computation steps.
   */
  createComputationPlan(parameters) {
    switch (this.algorithm) {
      case "average-glucose-by-medication":
        return [
          {
            operation: "filter",
            parameters: { timeRange: parameters.timeRange }
          },
          {
            operation: "aggregate",
            parameters: { field: "medication" }
          }
        ];
      case "statistical-analysis":
        return [
          {
            operation: "sum",
            parameters: {}
          },
          {
            operation: "average",
            parameters: {}
          }
        ];
      default:
        throw new Error(`Unsupported algorithm: ${this.algorithm}`);
    }
  }

  /**
   * Combines results from all nodes based on the algorithm.
   * In real SMPC, this would involve reconstructing the final output from secret shares securely.
   * @param {Array<Array<Object>>} nodeResults - Intermediate results from each computation step.
   * @param {Object[]} computationPlan - The computation plan executed.
   * @returns {Object} - The combined final result.
   */
  combineResults(nodeResults, computationPlan) {
    this.log("Combining results from all nodes");
    
    const finalStepResults = nodeResults[nodeResults.length - 1];
    
    switch (this.algorithm) {
      case "average-glucose-by-medication": {
        const combinedResults = {};
        
        finalStepResults.forEach(nodeResult => {
          Object.entries(nodeResult).forEach(([medication, data]) => {
            if (!combinedResults[medication]) {
              combinedResults[medication] = {
                count: 0,
                glucoseAverage: 0,
                ageAverage: 0,
                genderDistribution: { male: 0, female: 0 }
              };
            }
            
            const totalCount = combinedResults[medication].count + data.count;
            combinedResults[medication].glucoseAverage =
              (combinedResults[medication].glucoseAverage * combinedResults[medication].count +
               data.values.glucoseAverage * data.count) / totalCount;
            
            if (data.values.age) {
              combinedResults[medication].ageAverage =
                (combinedResults[medication].ageAverage * combinedResults[medication].count +
                 data.values.age * data.count) / totalCount;
            }
            
            if (data.values.gender === "male") {
              combinedResults[medication].genderDistribution.male += data.count;
            } else if (data.values.gender === "female") {
              combinedResults[medication].genderDistribution.female += data.count;
            }
            
            combinedResults[medication].count = totalCount;
          });
        });
        
        return {
          algorithm: this.algorithm,
          results: combinedResults,
          metadata: {
            totalPatients: Object.values(combinedResults).reduce((sum, data) => sum + data.count, 0),
            timeRange: computationPlan[0].parameters.timeRange
          }
        };
      }
      case "statistical-analysis": {
        const sumResults = {};
        let totalCount = 0;
        
        finalStepResults.forEach(nodeResult => {
          totalCount += nodeResult.count || 1;
          
          Object.entries(nodeResult).forEach(([key, value]) => {
            if (key !== "count" && typeof value === "number") {
              sumResults[key] = (sumResults[key] || 0) + value;
            }
          });
        });
        
        const avgResults = {};
        Object.entries(sumResults).forEach(([key, value]) => {
          avgResults[key] = value / totalCount;
        });
        
        return {
          algorithm: this.algorithm,
          results: {
            averages: avgResults,
            counts: { total: totalCount }
          }
        };
      }
      default:
        throw new Error(`Unsupported algorithm for result combination: ${this.algorithm}`);
    }
  }

  /**
   * Logs a message for protocol-level tracking.
   * @param {string} message - The message to log.
   */
  log(message) {
    this.logs.push(`[Protocol] ${message}`);
  }
}
