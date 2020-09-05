package android.support.constraint.solver.widgets;

import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.SolverVariable;
import android.support.constraint.solver.widgets.ConstraintAnchor;

public class ResolutionAnchor extends ResolutionNode {
    public static final int BARRIER_CONNECTION = 5;
    public static final int CENTER_CONNECTION = 2;
    public static final int CHAIN_CONNECTION = 4;
    public static final int DIRECT_CONNECTION = 1;
    public static final int MATCH_CONNECTION = 3;
    public static final int UNCONNECTED = 0;
    float computedValue;
    private ResolutionDimension dimension = null;
    private int dimensionMultiplier = 1;
    ConstraintAnchor myAnchor;
    float offset;
    private ResolutionAnchor opposite;
    private ResolutionDimension oppositeDimension = null;
    private int oppositeDimensionMultiplier = 1;
    private float oppositeOffset;
    float resolvedOffset;
    ResolutionAnchor resolvedTarget;
    ResolutionAnchor target;
    int type = 0;

    public ResolutionAnchor(ConstraintAnchor anchor) {
        this.myAnchor = anchor;
    }

    @Override // android.support.constraint.solver.widgets.ResolutionNode
    public void remove(ResolutionDimension resolutionDimension) {
        if (this.dimension == resolutionDimension) {
            this.dimension = null;
            this.offset = (float) this.dimensionMultiplier;
        } else if (this.dimension == this.oppositeDimension) {
            this.oppositeDimension = null;
            this.oppositeOffset = (float) this.oppositeDimensionMultiplier;
        }
        resolve();
    }

    public String toString() {
        if (this.state != 1) {
            return "{ " + this.myAnchor + " UNRESOLVED} type: " + sType(this.type);
        } else if (this.resolvedTarget == this) {
            return "[" + this.myAnchor + ", RESOLVED: " + this.resolvedOffset + "]  type: " + sType(this.type);
        } else {
            return "[" + this.myAnchor + ", RESOLVED: " + this.resolvedTarget + ":" + this.resolvedOffset + "] type: " + sType(this.type);
        }
    }

    public void resolve(ResolutionAnchor target2, float offset2) {
        if (this.state == 0 || !(this.resolvedTarget == target2 || this.resolvedOffset == offset2)) {
            this.resolvedTarget = target2;
            this.resolvedOffset = offset2;
            if (this.state == 1) {
                invalidate();
            }
            didResolve();
        }
    }

    /* access modifiers changed from: package-private */
    public String sType(int type2) {
        if (type2 == 1) {
            return "DIRECT";
        }
        if (type2 == 2) {
            return "CENTER";
        }
        if (type2 == 3) {
            return "MATCH";
        }
        if (type2 == 4) {
            return "CHAIN";
        }
        if (type2 == 5) {
            return "BARRIER";
        }
        return "UNCONNECTED";
    }

    @Override // android.support.constraint.solver.widgets.ResolutionNode
    public void resolve() {
        float distance;
        float distance2;
        float percent;
        boolean isEndAnchor = true;
        if (this.state != 1 && this.type != 4) {
            if (this.dimension != null) {
                if (this.dimension.state == 1) {
                    this.offset = ((float) this.dimensionMultiplier) * this.dimension.value;
                } else {
                    return;
                }
            }
            if (this.oppositeDimension != null) {
                if (this.oppositeDimension.state == 1) {
                    this.oppositeOffset = ((float) this.oppositeDimensionMultiplier) * this.oppositeDimension.value;
                } else {
                    return;
                }
            }
            if (this.type == 1 && (this.target == null || this.target.state == 1)) {
                if (this.target == null) {
                    this.resolvedTarget = this;
                    this.resolvedOffset = this.offset;
                } else {
                    this.resolvedTarget = this.target.resolvedTarget;
                    this.resolvedOffset = this.target.resolvedOffset + this.offset;
                }
                didResolve();
            } else if (this.type == 2 && this.target != null && this.target.state == 1 && this.opposite != null && this.opposite.target != null && this.opposite.target.state == 1) {
                if (LinearSystem.getMetrics() != null) {
                    LinearSystem.getMetrics().centerConnectionResolved++;
                }
                this.resolvedTarget = this.target.resolvedTarget;
                this.opposite.resolvedTarget = this.opposite.target.resolvedTarget;
                if (!(this.myAnchor.mType == ConstraintAnchor.Type.RIGHT || this.myAnchor.mType == ConstraintAnchor.Type.BOTTOM)) {
                    isEndAnchor = false;
                }
                if (isEndAnchor) {
                    distance = this.target.resolvedOffset - this.opposite.target.resolvedOffset;
                } else {
                    distance = this.opposite.target.resolvedOffset - this.target.resolvedOffset;
                }
                if (this.myAnchor.mType == ConstraintAnchor.Type.LEFT || this.myAnchor.mType == ConstraintAnchor.Type.RIGHT) {
                    distance2 = distance - ((float) this.myAnchor.mOwner.getWidth());
                    percent = this.myAnchor.mOwner.mHorizontalBiasPercent;
                } else {
                    distance2 = distance - ((float) this.myAnchor.mOwner.getHeight());
                    percent = this.myAnchor.mOwner.mVerticalBiasPercent;
                }
                int margin = this.myAnchor.getMargin();
                int oppositeMargin = this.opposite.myAnchor.getMargin();
                if (this.myAnchor.getTarget() == this.opposite.myAnchor.getTarget()) {
                    percent = 0.5f;
                    margin = 0;
                    oppositeMargin = 0;
                }
                float distance3 = (distance2 - ((float) margin)) - ((float) oppositeMargin);
                if (isEndAnchor) {
                    this.opposite.resolvedOffset = this.opposite.target.resolvedOffset + ((float) oppositeMargin) + (distance3 * percent);
                    this.resolvedOffset = (this.target.resolvedOffset - ((float) margin)) - ((1.0f - percent) * distance3);
                } else {
                    this.resolvedOffset = this.target.resolvedOffset + ((float) margin) + (distance3 * percent);
                    this.opposite.resolvedOffset = (this.opposite.target.resolvedOffset - ((float) oppositeMargin)) - ((1.0f - percent) * distance3);
                }
                didResolve();
                this.opposite.didResolve();
            } else if (this.type == 3 && this.target != null && this.target.state == 1 && this.opposite != null && this.opposite.target != null && this.opposite.target.state == 1) {
                if (LinearSystem.getMetrics() != null) {
                    LinearSystem.getMetrics().matchConnectionResolved++;
                }
                this.resolvedTarget = this.target.resolvedTarget;
                this.opposite.resolvedTarget = this.opposite.target.resolvedTarget;
                this.resolvedOffset = this.target.resolvedOffset + this.offset;
                this.opposite.resolvedOffset = this.opposite.target.resolvedOffset + this.opposite.offset;
                didResolve();
                this.opposite.didResolve();
            } else if (this.type == 5) {
                this.myAnchor.mOwner.resolve();
            }
        }
    }

    public void setType(int type2) {
        this.type = type2;
    }

    @Override // android.support.constraint.solver.widgets.ResolutionNode
    public void reset() {
        super.reset();
        this.target = null;
        this.offset = 0.0f;
        this.dimension = null;
        this.dimensionMultiplier = 1;
        this.oppositeDimension = null;
        this.oppositeDimensionMultiplier = 1;
        this.resolvedTarget = null;
        this.resolvedOffset = 0.0f;
        this.computedValue = 0.0f;
        this.opposite = null;
        this.oppositeOffset = 0.0f;
        this.type = 0;
    }

    public void update() {
        ConstraintAnchor targetAnchor = this.myAnchor.getTarget();
        if (targetAnchor != null) {
            if (targetAnchor.getTarget() == this.myAnchor) {
                this.type = 4;
                targetAnchor.getResolutionNode().type = 4;
            }
            int margin = this.myAnchor.getMargin();
            if (this.myAnchor.mType == ConstraintAnchor.Type.RIGHT || this.myAnchor.mType == ConstraintAnchor.Type.BOTTOM) {
                margin = -margin;
            }
            dependsOn(targetAnchor.getResolutionNode(), margin);
        }
    }

    public void dependsOn(int type2, ResolutionAnchor node, int offset2) {
        this.type = type2;
        this.target = node;
        this.offset = (float) offset2;
        this.target.addDependent(this);
    }

    public void dependsOn(ResolutionAnchor node, int offset2) {
        this.target = node;
        this.offset = (float) offset2;
        this.target.addDependent(this);
    }

    public void dependsOn(ResolutionAnchor node, int multiplier, ResolutionDimension dimension2) {
        this.target = node;
        this.target.addDependent(this);
        this.dimension = dimension2;
        this.dimensionMultiplier = multiplier;
        this.dimension.addDependent(this);
    }

    public void setOpposite(ResolutionAnchor opposite2, float oppositeOffset2) {
        this.opposite = opposite2;
        this.oppositeOffset = oppositeOffset2;
    }

    public void setOpposite(ResolutionAnchor opposite2, int multiplier, ResolutionDimension dimension2) {
        this.opposite = opposite2;
        this.oppositeDimension = dimension2;
        this.oppositeDimensionMultiplier = multiplier;
    }

    /* access modifiers changed from: package-private */
    public void addResolvedValue(LinearSystem system) {
        SolverVariable sv = this.myAnchor.getSolverVariable();
        if (this.resolvedTarget == null) {
            system.addEquality(sv, (int) (this.resolvedOffset + 0.5f));
        } else {
            system.addEquality(sv, system.createObjectVariable(this.resolvedTarget.myAnchor), (int) (this.resolvedOffset + 0.5f), 6);
        }
    }

    public float getResolvedValue() {
        return this.resolvedOffset;
    }
}
