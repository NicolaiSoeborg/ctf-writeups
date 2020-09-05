package android.support.constraint.solver.widgets;

import android.support.constraint.solver.LinearSystem;
import android.support.constraint.solver.SolverVariable;
import android.support.constraint.solver.widgets.ConstraintAnchor;
import android.support.constraint.solver.widgets.ConstraintWidget;
import java.util.ArrayList;

public class Guideline extends ConstraintWidget {
    public static final int HORIZONTAL = 0;
    public static final int RELATIVE_BEGIN = 1;
    public static final int RELATIVE_END = 2;
    public static final int RELATIVE_PERCENT = 0;
    public static final int RELATIVE_UNKNWON = -1;
    public static final int VERTICAL = 1;
    private ConstraintAnchor mAnchor = this.mTop;
    private Rectangle mHead;
    private int mHeadSize;
    private boolean mIsPositionRelaxed;
    private int mMinimumPosition;
    private int mOrientation;
    protected int mRelativeBegin = -1;
    protected int mRelativeEnd = -1;
    protected float mRelativePercent = -1.0f;

    public Guideline() {
        this.mOrientation = 0;
        this.mIsPositionRelaxed = false;
        this.mMinimumPosition = 0;
        this.mHead = new Rectangle();
        this.mHeadSize = 8;
        this.mAnchors.clear();
        this.mAnchors.add(this.mAnchor);
        int count = this.mListAnchors.length;
        for (int i = 0; i < count; i++) {
            this.mListAnchors[i] = this.mAnchor;
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public boolean allowedInBarrier() {
        return true;
    }

    public int getRelativeBehaviour() {
        if (this.mRelativePercent != -1.0f) {
            return 0;
        }
        if (this.mRelativeBegin != -1) {
            return 1;
        }
        if (this.mRelativeEnd != -1) {
            return 2;
        }
        return -1;
    }

    public Rectangle getHead() {
        this.mHead.setBounds(getDrawX() - this.mHeadSize, getDrawY() - (this.mHeadSize * 2), this.mHeadSize * 2, this.mHeadSize * 2);
        if (getOrientation() == 0) {
            this.mHead.setBounds(getDrawX() - (this.mHeadSize * 2), getDrawY() - this.mHeadSize, this.mHeadSize * 2, this.mHeadSize * 2);
        }
        return this.mHead;
    }

    public void setOrientation(int orientation) {
        if (this.mOrientation != orientation) {
            this.mOrientation = orientation;
            this.mAnchors.clear();
            if (this.mOrientation == 1) {
                this.mAnchor = this.mLeft;
            } else {
                this.mAnchor = this.mTop;
            }
            this.mAnchors.add(this.mAnchor);
            int count = this.mListAnchors.length;
            for (int i = 0; i < count; i++) {
                this.mListAnchors[i] = this.mAnchor;
            }
        }
    }

    public ConstraintAnchor getAnchor() {
        return this.mAnchor;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public String getType() {
        return "Guideline";
    }

    public int getOrientation() {
        return this.mOrientation;
    }

    public void setMinimumPosition(int minimum) {
        this.mMinimumPosition = minimum;
    }

    public void setPositionRelaxed(boolean value) {
        if (this.mIsPositionRelaxed != value) {
            this.mIsPositionRelaxed = value;
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public ConstraintAnchor getAnchor(ConstraintAnchor.Type anchorType) {
        switch (anchorType) {
            case LEFT:
            case RIGHT:
                if (this.mOrientation == 1) {
                    return this.mAnchor;
                }
                break;
            case TOP:
            case BOTTOM:
                if (this.mOrientation == 0) {
                    return this.mAnchor;
                }
                break;
            case BASELINE:
            case CENTER:
            case CENTER_X:
            case CENTER_Y:
            case NONE:
                return null;
        }
        throw new AssertionError(anchorType.name());
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public ArrayList<ConstraintAnchor> getAnchors() {
        return this.mAnchors;
    }

    public void setGuidePercent(int value) {
        setGuidePercent(((float) value) / 100.0f);
    }

    public void setGuidePercent(float value) {
        if (value > -1.0f) {
            this.mRelativePercent = value;
            this.mRelativeBegin = -1;
            this.mRelativeEnd = -1;
        }
    }

    public void setGuideBegin(int value) {
        if (value > -1) {
            this.mRelativePercent = -1.0f;
            this.mRelativeBegin = value;
            this.mRelativeEnd = -1;
        }
    }

    public void setGuideEnd(int value) {
        if (value > -1) {
            this.mRelativePercent = -1.0f;
            this.mRelativeBegin = -1;
            this.mRelativeEnd = value;
        }
    }

    public float getRelativePercent() {
        return this.mRelativePercent;
    }

    public int getRelativeBegin() {
        return this.mRelativeBegin;
    }

    public int getRelativeEnd() {
        return this.mRelativeEnd;
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void analyze(int optimizationLevel) {
        ConstraintWidget constraintWidgetContainer = getParent();
        if (constraintWidgetContainer != null) {
            if (getOrientation() == 1) {
                this.mTop.getResolutionNode().dependsOn(1, constraintWidgetContainer.mTop.getResolutionNode(), 0);
                this.mBottom.getResolutionNode().dependsOn(1, constraintWidgetContainer.mTop.getResolutionNode(), 0);
                if (this.mRelativeBegin != -1) {
                    this.mLeft.getResolutionNode().dependsOn(1, constraintWidgetContainer.mLeft.getResolutionNode(), this.mRelativeBegin);
                    this.mRight.getResolutionNode().dependsOn(1, constraintWidgetContainer.mLeft.getResolutionNode(), this.mRelativeBegin);
                } else if (this.mRelativeEnd != -1) {
                    this.mLeft.getResolutionNode().dependsOn(1, constraintWidgetContainer.mRight.getResolutionNode(), -this.mRelativeEnd);
                    this.mRight.getResolutionNode().dependsOn(1, constraintWidgetContainer.mRight.getResolutionNode(), -this.mRelativeEnd);
                } else if (this.mRelativePercent != -1.0f && constraintWidgetContainer.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED) {
                    int position = (int) (((float) constraintWidgetContainer.mWidth) * this.mRelativePercent);
                    this.mLeft.getResolutionNode().dependsOn(1, constraintWidgetContainer.mLeft.getResolutionNode(), position);
                    this.mRight.getResolutionNode().dependsOn(1, constraintWidgetContainer.mLeft.getResolutionNode(), position);
                }
            } else {
                this.mLeft.getResolutionNode().dependsOn(1, constraintWidgetContainer.mLeft.getResolutionNode(), 0);
                this.mRight.getResolutionNode().dependsOn(1, constraintWidgetContainer.mLeft.getResolutionNode(), 0);
                if (this.mRelativeBegin != -1) {
                    this.mTop.getResolutionNode().dependsOn(1, constraintWidgetContainer.mTop.getResolutionNode(), this.mRelativeBegin);
                    this.mBottom.getResolutionNode().dependsOn(1, constraintWidgetContainer.mTop.getResolutionNode(), this.mRelativeBegin);
                } else if (this.mRelativeEnd != -1) {
                    this.mTop.getResolutionNode().dependsOn(1, constraintWidgetContainer.mBottom.getResolutionNode(), -this.mRelativeEnd);
                    this.mBottom.getResolutionNode().dependsOn(1, constraintWidgetContainer.mBottom.getResolutionNode(), -this.mRelativeEnd);
                } else if (this.mRelativePercent != -1.0f && constraintWidgetContainer.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.FIXED) {
                    int position2 = (int) (((float) constraintWidgetContainer.mHeight) * this.mRelativePercent);
                    this.mTop.getResolutionNode().dependsOn(1, constraintWidgetContainer.mTop.getResolutionNode(), position2);
                    this.mBottom.getResolutionNode().dependsOn(1, constraintWidgetContainer.mTop.getResolutionNode(), position2);
                }
            }
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void addToSolver(LinearSystem system) {
        ConstraintWidgetContainer parent = (ConstraintWidgetContainer) getParent();
        if (parent != null) {
            ConstraintAnchor begin = parent.getAnchor(ConstraintAnchor.Type.LEFT);
            ConstraintAnchor end = parent.getAnchor(ConstraintAnchor.Type.RIGHT);
            boolean z = true;
            boolean parentWrapContent = this.mParent != null && this.mParent.mListDimensionBehaviors[0] == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
            if (this.mOrientation == 0) {
                begin = parent.getAnchor(ConstraintAnchor.Type.TOP);
                end = parent.getAnchor(ConstraintAnchor.Type.BOTTOM);
                if (this.mParent == null || this.mParent.mListDimensionBehaviors[1] != ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                    z = false;
                }
                parentWrapContent = z;
            }
            if (this.mRelativeBegin != -1) {
                SolverVariable guide = system.createObjectVariable(this.mAnchor);
                system.addEquality(guide, system.createObjectVariable(begin), this.mRelativeBegin, 6);
                if (parentWrapContent) {
                    system.addGreaterThan(system.createObjectVariable(end), guide, 0, 5);
                }
            } else if (this.mRelativeEnd != -1) {
                SolverVariable guide2 = system.createObjectVariable(this.mAnchor);
                SolverVariable parentRight = system.createObjectVariable(end);
                system.addEquality(guide2, parentRight, -this.mRelativeEnd, 6);
                if (parentWrapContent) {
                    system.addGreaterThan(guide2, system.createObjectVariable(begin), 0, 5);
                    system.addGreaterThan(parentRight, guide2, 0, 5);
                }
            } else if (this.mRelativePercent != -1.0f) {
                system.addConstraint(LinearSystem.createRowDimensionPercent(system, system.createObjectVariable(this.mAnchor), system.createObjectVariable(begin), system.createObjectVariable(end), this.mRelativePercent, this.mIsPositionRelaxed));
            }
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void updateFromSolver(LinearSystem system) {
        if (getParent() != null) {
            int value = system.getObjectVariableValue(this.mAnchor);
            if (this.mOrientation == 1) {
                setX(value);
                setY(0);
                setHeight(getParent().getHeight());
                setWidth(0);
                return;
            }
            setX(0);
            setY(value);
            setWidth(getParent().getWidth());
            setHeight(0);
        }
    }

    @Override // android.support.constraint.solver.widgets.ConstraintWidget
    public void setDrawOrigin(int x, int y) {
        if (this.mOrientation == 1) {
            int position = x - this.mOffsetX;
            if (this.mRelativeBegin != -1) {
                setGuideBegin(position);
            } else if (this.mRelativeEnd != -1) {
                setGuideEnd(getParent().getWidth() - position);
            } else if (this.mRelativePercent != -1.0f) {
                setGuidePercent(((float) position) / ((float) getParent().getWidth()));
            }
        } else {
            int position2 = y - this.mOffsetY;
            if (this.mRelativeBegin != -1) {
                setGuideBegin(position2);
            } else if (this.mRelativeEnd != -1) {
                setGuideEnd(getParent().getHeight() - position2);
            } else if (this.mRelativePercent != -1.0f) {
                setGuidePercent(((float) position2) / ((float) getParent().getHeight()));
            }
        }
    }

    /* access modifiers changed from: package-private */
    public void inferRelativePercentPosition() {
        float percent = ((float) getX()) / ((float) getParent().getWidth());
        if (this.mOrientation == 0) {
            percent = ((float) getY()) / ((float) getParent().getHeight());
        }
        setGuidePercent(percent);
    }

    /* access modifiers changed from: package-private */
    public void inferRelativeBeginPosition() {
        int position = getX();
        if (this.mOrientation == 0) {
            position = getY();
        }
        setGuideBegin(position);
    }

    /* access modifiers changed from: package-private */
    public void inferRelativeEndPosition() {
        int position = getParent().getWidth() - getX();
        if (this.mOrientation == 0) {
            position = getParent().getHeight() - getY();
        }
        setGuideEnd(position);
    }

    public void cyclePosition() {
        if (this.mRelativeBegin != -1) {
            inferRelativePercentPosition();
        } else if (this.mRelativePercent != -1.0f) {
            inferRelativeEndPosition();
        } else if (this.mRelativeEnd != -1) {
            inferRelativeBeginPosition();
        }
    }
}
