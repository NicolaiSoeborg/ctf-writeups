package android.support.constraint.solver;

import android.support.constraint.solver.SolverVariable;
import com.google.ctf.sandbox.BuildConfig;
import java.io.PrintStream;
import java.util.Arrays;

public class ArrayLinkedVariables {
    private static final boolean DEBUG = false;
    private static final boolean FULL_NEW_CHECK = false;
    private static final int NONE = -1;
    private int ROW_SIZE = 8;
    private SolverVariable candidate = null;
    int currentSize = 0;
    private int[] mArrayIndices = new int[this.ROW_SIZE];
    private int[] mArrayNextIndices = new int[this.ROW_SIZE];
    private float[] mArrayValues = new float[this.ROW_SIZE];
    private final Cache mCache;
    private boolean mDidFillOnce = false;
    private int mHead = -1;
    private int mLast = -1;
    private final ArrayRow mRow;

    ArrayLinkedVariables(ArrayRow arrayRow, Cache cache) {
        this.mRow = arrayRow;
        this.mCache = cache;
    }

    public final void put(SolverVariable variable, float value) {
        if (value == 0.0f) {
            remove(variable, true);
        } else if (this.mHead == -1) {
            this.mHead = 0;
            this.mArrayValues[this.mHead] = value;
            this.mArrayIndices[this.mHead] = variable.id;
            this.mArrayNextIndices[this.mHead] = -1;
            variable.usageInRowCount++;
            variable.addToRow(this.mRow);
            this.currentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
                if (this.mLast >= this.mArrayIndices.length) {
                    this.mDidFillOnce = true;
                    this.mLast = this.mArrayIndices.length - 1;
                }
            }
        } else {
            int previous = -1;
            int current = this.mHead;
            int counter = 0;
            while (current != -1 && counter < this.currentSize) {
                if (this.mArrayIndices[current] == variable.id) {
                    this.mArrayValues[current] = value;
                    return;
                }
                if (this.mArrayIndices[current] < variable.id) {
                    previous = current;
                }
                current = this.mArrayNextIndices[current];
                counter++;
            }
            int availableIndice = this.mLast + 1;
            if (this.mDidFillOnce) {
                if (this.mArrayIndices[this.mLast] == -1) {
                    availableIndice = this.mLast;
                } else {
                    availableIndice = this.mArrayIndices.length;
                }
            }
            if (availableIndice >= this.mArrayIndices.length && this.currentSize < this.mArrayIndices.length) {
                int i = 0;
                while (true) {
                    if (i >= this.mArrayIndices.length) {
                        break;
                    } else if (this.mArrayIndices[i] == -1) {
                        availableIndice = i;
                        break;
                    } else {
                        i++;
                    }
                }
            }
            if (availableIndice >= this.mArrayIndices.length) {
                availableIndice = this.mArrayIndices.length;
                this.ROW_SIZE *= 2;
                this.mDidFillOnce = false;
                this.mLast = availableIndice - 1;
                this.mArrayValues = Arrays.copyOf(this.mArrayValues, this.ROW_SIZE);
                this.mArrayIndices = Arrays.copyOf(this.mArrayIndices, this.ROW_SIZE);
                this.mArrayNextIndices = Arrays.copyOf(this.mArrayNextIndices, this.ROW_SIZE);
            }
            this.mArrayIndices[availableIndice] = variable.id;
            this.mArrayValues[availableIndice] = value;
            if (previous != -1) {
                this.mArrayNextIndices[availableIndice] = this.mArrayNextIndices[previous];
                this.mArrayNextIndices[previous] = availableIndice;
            } else {
                this.mArrayNextIndices[availableIndice] = this.mHead;
                this.mHead = availableIndice;
            }
            variable.usageInRowCount++;
            variable.addToRow(this.mRow);
            this.currentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
            }
            if (this.currentSize >= this.mArrayIndices.length) {
                this.mDidFillOnce = true;
            }
            if (this.mLast >= this.mArrayIndices.length) {
                this.mDidFillOnce = true;
                this.mLast = this.mArrayIndices.length - 1;
            }
        }
    }

    /* access modifiers changed from: package-private */
    public final void add(SolverVariable variable, float value, boolean removeFromDefinition) {
        if (value != 0.0f) {
            if (this.mHead == -1) {
                this.mHead = 0;
                this.mArrayValues[this.mHead] = value;
                this.mArrayIndices[this.mHead] = variable.id;
                this.mArrayNextIndices[this.mHead] = -1;
                variable.usageInRowCount++;
                variable.addToRow(this.mRow);
                this.currentSize++;
                if (!this.mDidFillOnce) {
                    this.mLast++;
                    if (this.mLast >= this.mArrayIndices.length) {
                        this.mDidFillOnce = true;
                        this.mLast = this.mArrayIndices.length - 1;
                        return;
                    }
                    return;
                }
                return;
            }
            int previous = -1;
            int current = this.mHead;
            int counter = 0;
            while (current != -1 && counter < this.currentSize) {
                if (this.mArrayIndices[current] == variable.id) {
                    float[] fArr = this.mArrayValues;
                    fArr[current] = fArr[current] + value;
                    if (this.mArrayValues[current] == 0.0f) {
                        if (current == this.mHead) {
                            this.mHead = this.mArrayNextIndices[current];
                        } else {
                            this.mArrayNextIndices[previous] = this.mArrayNextIndices[current];
                        }
                        if (removeFromDefinition) {
                            variable.removeFromRow(this.mRow);
                        }
                        if (this.mDidFillOnce) {
                            this.mLast = current;
                        }
                        variable.usageInRowCount--;
                        this.currentSize--;
                        return;
                    }
                    return;
                }
                if (this.mArrayIndices[current] < variable.id) {
                    previous = current;
                }
                current = this.mArrayNextIndices[current];
                counter++;
            }
            int availableIndice = this.mLast + 1;
            if (this.mDidFillOnce) {
                if (this.mArrayIndices[this.mLast] == -1) {
                    availableIndice = this.mLast;
                } else {
                    availableIndice = this.mArrayIndices.length;
                }
            }
            if (availableIndice >= this.mArrayIndices.length && this.currentSize < this.mArrayIndices.length) {
                int i = 0;
                while (true) {
                    if (i >= this.mArrayIndices.length) {
                        break;
                    } else if (this.mArrayIndices[i] == -1) {
                        availableIndice = i;
                        break;
                    } else {
                        i++;
                    }
                }
            }
            if (availableIndice >= this.mArrayIndices.length) {
                availableIndice = this.mArrayIndices.length;
                this.ROW_SIZE *= 2;
                this.mDidFillOnce = false;
                this.mLast = availableIndice - 1;
                this.mArrayValues = Arrays.copyOf(this.mArrayValues, this.ROW_SIZE);
                this.mArrayIndices = Arrays.copyOf(this.mArrayIndices, this.ROW_SIZE);
                this.mArrayNextIndices = Arrays.copyOf(this.mArrayNextIndices, this.ROW_SIZE);
            }
            this.mArrayIndices[availableIndice] = variable.id;
            this.mArrayValues[availableIndice] = value;
            if (previous != -1) {
                this.mArrayNextIndices[availableIndice] = this.mArrayNextIndices[previous];
                this.mArrayNextIndices[previous] = availableIndice;
            } else {
                this.mArrayNextIndices[availableIndice] = this.mHead;
                this.mHead = availableIndice;
            }
            variable.usageInRowCount++;
            variable.addToRow(this.mRow);
            this.currentSize++;
            if (!this.mDidFillOnce) {
                this.mLast++;
            }
            if (this.mLast >= this.mArrayIndices.length) {
                this.mDidFillOnce = true;
                this.mLast = this.mArrayIndices.length - 1;
            }
        }
    }

    public final float remove(SolverVariable variable, boolean removeFromDefinition) {
        if (this.candidate == variable) {
            this.candidate = null;
        }
        if (this.mHead == -1) {
            return 0.0f;
        }
        int current = this.mHead;
        int previous = -1;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == variable.id) {
                if (current == this.mHead) {
                    this.mHead = this.mArrayNextIndices[current];
                } else {
                    this.mArrayNextIndices[previous] = this.mArrayNextIndices[current];
                }
                if (removeFromDefinition) {
                    variable.removeFromRow(this.mRow);
                }
                variable.usageInRowCount--;
                this.currentSize--;
                this.mArrayIndices[current] = -1;
                if (this.mDidFillOnce) {
                    this.mLast = current;
                }
                return this.mArrayValues[current];
            }
            previous = current;
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return 0.0f;
    }

    public final void clear() {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            SolverVariable variable = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            if (variable != null) {
                variable.removeFromRow(this.mRow);
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        this.mHead = -1;
        this.mLast = -1;
        this.mDidFillOnce = false;
        this.currentSize = 0;
    }

    /* access modifiers changed from: package-private */
    public final boolean containsKey(SolverVariable variable) {
        if (this.mHead == -1) {
            return false;
        }
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == variable.id) {
                return true;
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return false;
    }

    /* access modifiers changed from: package-private */
    public boolean hasAtLeastOnePositiveVariable() {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayValues[current] > 0.0f) {
                return true;
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return false;
    }

    /* access modifiers changed from: package-private */
    public void invert() {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            float[] fArr = this.mArrayValues;
            fArr[current] = fArr[current] * -1.0f;
            current = this.mArrayNextIndices[current];
            counter++;
        }
    }

    /* access modifiers changed from: package-private */
    public void divideByAmount(float amount) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            float[] fArr = this.mArrayValues;
            fArr[current] = fArr[current] / amount;
            current = this.mArrayNextIndices[current];
            counter++;
        }
    }

    private boolean isNew(SolverVariable variable, LinearSystem system) {
        return variable.usageInRowCount <= 1;
    }

    /* access modifiers changed from: package-private */
    public SolverVariable chooseSubject(LinearSystem system) {
        SolverVariable unrestrictedCandidate = null;
        int current = this.mHead;
        int counter = 0;
        float f = 0.0f;
        boolean restrictedCandidateIsNew = false;
        boolean unrestrictedCandidateIsNew = false;
        float restrictedCandidateAmount = 0.0f;
        float unrestrictedCandidateAmount = 0.0f;
        SolverVariable restrictedCandidate = null;
        while (current != -1 && counter < this.currentSize) {
            float amount = this.mArrayValues[current];
            SolverVariable variable = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            if (amount < f) {
                if (amount > (-0.001f)) {
                    this.mArrayValues[current] = f;
                    amount = 0.0f;
                    variable.removeFromRow(this.mRow);
                }
            } else if (amount < 0.001f) {
                this.mArrayValues[current] = f;
                amount = 0.0f;
                variable.removeFromRow(this.mRow);
            }
            if (amount != f) {
                if (variable.mType == SolverVariable.Type.UNRESTRICTED) {
                    if (unrestrictedCandidate == null) {
                        unrestrictedCandidate = variable;
                        unrestrictedCandidateAmount = amount;
                        unrestrictedCandidateIsNew = isNew(variable, system);
                    } else if (unrestrictedCandidateAmount > amount) {
                        unrestrictedCandidate = variable;
                        unrestrictedCandidateAmount = amount;
                        unrestrictedCandidateIsNew = isNew(variable, system);
                    } else if (!unrestrictedCandidateIsNew && isNew(variable, system)) {
                        unrestrictedCandidate = variable;
                        unrestrictedCandidateAmount = amount;
                        unrestrictedCandidateIsNew = true;
                    }
                } else if (unrestrictedCandidate == null) {
                    f = 0.0f;
                    if (amount < 0.0f) {
                        if (restrictedCandidate == null) {
                            restrictedCandidate = variable;
                            restrictedCandidateAmount = amount;
                            restrictedCandidateIsNew = isNew(variable, system);
                        } else if (restrictedCandidateAmount > amount) {
                            restrictedCandidate = variable;
                            restrictedCandidateAmount = amount;
                            restrictedCandidateIsNew = isNew(variable, system);
                        } else if (!restrictedCandidateIsNew && isNew(variable, system)) {
                            restrictedCandidate = variable;
                            restrictedCandidateAmount = amount;
                            restrictedCandidateIsNew = true;
                        }
                    }
                }
                f = 0.0f;
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        if (unrestrictedCandidate != null) {
            return unrestrictedCandidate;
        }
        return restrictedCandidate;
    }

    /* access modifiers changed from: package-private */
    public final void updateFromRow(ArrayRow self, ArrayRow definition, boolean removeFromDefinition) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == definition.variable.id) {
                float value = this.mArrayValues[current];
                remove(definition.variable, removeFromDefinition);
                ArrayLinkedVariables definitionVariables = definition.variables;
                int definitionCurrent = definitionVariables.mHead;
                int definitionCounter = 0;
                while (definitionCurrent != -1 && definitionCounter < definitionVariables.currentSize) {
                    add(this.mCache.mIndexedVariables[definitionVariables.mArrayIndices[definitionCurrent]], definitionVariables.mArrayValues[definitionCurrent] * value, removeFromDefinition);
                    definitionCurrent = definitionVariables.mArrayNextIndices[definitionCurrent];
                    definitionCounter++;
                }
                self.constantValue += definition.constantValue * value;
                if (removeFromDefinition) {
                    definition.variable.removeFromRow(self);
                }
                current = this.mHead;
                counter = 0;
            } else {
                current = this.mArrayNextIndices[current];
                counter++;
            }
        }
    }

    /* access modifiers changed from: package-private */
    public void updateFromSystem(ArrayRow self, ArrayRow[] rows) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            SolverVariable variable = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            if (variable.definitionId != -1) {
                float value = this.mArrayValues[current];
                remove(variable, true);
                ArrayRow definition = rows[variable.definitionId];
                if (!definition.isSimpleDefinition) {
                    ArrayLinkedVariables definitionVariables = definition.variables;
                    int definitionCurrent = definitionVariables.mHead;
                    int definitionCounter = 0;
                    while (definitionCurrent != -1 && definitionCounter < definitionVariables.currentSize) {
                        add(this.mCache.mIndexedVariables[definitionVariables.mArrayIndices[definitionCurrent]], definitionVariables.mArrayValues[definitionCurrent] * value, true);
                        definitionCurrent = definitionVariables.mArrayNextIndices[definitionCurrent];
                        definitionCounter++;
                    }
                }
                self.constantValue += definition.constantValue * value;
                definition.variable.removeFromRow(self);
                current = this.mHead;
                counter = 0;
            } else {
                current = this.mArrayNextIndices[current];
                counter++;
            }
        }
    }

    /* access modifiers changed from: package-private */
    public SolverVariable getPivotCandidate() {
        if (this.candidate != null) {
            return this.candidate;
        }
        int current = this.mHead;
        int counter = 0;
        SolverVariable pivot = null;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayValues[current] < 0.0f) {
                SolverVariable v = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
                if (pivot == null || pivot.strength < v.strength) {
                    pivot = v;
                }
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return pivot;
    }

    /* access modifiers changed from: package-private */
    public SolverVariable getPivotCandidate(boolean[] avoid, SolverVariable exclude) {
        SolverVariable pivot = null;
        int counter = 0;
        int current = this.mHead;
        float value = 0.0f;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayValues[current] < 0.0f) {
                SolverVariable v = this.mCache.mIndexedVariables[this.mArrayIndices[current]];
                if ((avoid == null || !avoid[v.id]) && v != exclude && (v.mType == SolverVariable.Type.SLACK || v.mType == SolverVariable.Type.ERROR)) {
                    float currentValue = this.mArrayValues[current];
                    if (currentValue < value) {
                        value = currentValue;
                        pivot = v;
                    }
                }
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return pivot;
    }

    /* access modifiers changed from: package-private */
    public final SolverVariable getVariable(int index) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (counter == index) {
                return this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    public final float getVariableValue(int index) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (counter == index) {
                return this.mArrayValues[current];
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return 0.0f;
    }

    public final float get(SolverVariable v) {
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            if (this.mArrayIndices[current] == v.id) {
                return this.mArrayValues[current];
            }
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return 0.0f;
    }

    /* access modifiers changed from: package-private */
    public int sizeInBytes() {
        return 0 + (this.mArrayIndices.length * 4 * 3) + 36;
    }

    public void display() {
        int count = this.currentSize;
        System.out.print("{ ");
        for (int i = 0; i < count; i++) {
            SolverVariable v = getVariable(i);
            if (v != null) {
                PrintStream printStream = System.out;
                printStream.print(v + " = " + getVariableValue(i) + " ");
            }
        }
        System.out.println(" }");
    }

    public String toString() {
        String result = BuildConfig.FLAVOR;
        int current = this.mHead;
        int counter = 0;
        while (current != -1 && counter < this.currentSize) {
            result = ((result + " -> ") + this.mArrayValues[current] + " : ") + this.mCache.mIndexedVariables[this.mArrayIndices[current]];
            current = this.mArrayNextIndices[current];
            counter++;
        }
        return result;
    }
}
