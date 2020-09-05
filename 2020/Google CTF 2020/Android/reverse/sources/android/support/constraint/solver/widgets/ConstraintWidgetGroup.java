package android.support.constraint.solver.widgets;

import android.support.constraint.solver.widgets.ConstraintAnchor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ConstraintWidgetGroup {
    public List<ConstraintWidget> mConstrainedGroup;
    public final int[] mGroupDimensions = {this.mGroupWidth, this.mGroupHeight};
    int mGroupHeight = -1;
    int mGroupWidth = -1;
    public boolean mSkipSolver = false;
    List<ConstraintWidget> mStartHorizontalWidgets = new ArrayList();
    List<ConstraintWidget> mStartVerticalWidgets = new ArrayList();
    List<ConstraintWidget> mUnresolvedWidgets = new ArrayList();
    HashSet<ConstraintWidget> mWidgetsToSetHorizontal = new HashSet<>();
    HashSet<ConstraintWidget> mWidgetsToSetVertical = new HashSet<>();
    List<ConstraintWidget> mWidgetsToSolve = new ArrayList();

    ConstraintWidgetGroup(List<ConstraintWidget> widgets) {
        this.mConstrainedGroup = widgets;
    }

    ConstraintWidgetGroup(List<ConstraintWidget> widgets, boolean skipSolver) {
        this.mConstrainedGroup = widgets;
        this.mSkipSolver = skipSolver;
    }

    public List<ConstraintWidget> getStartWidgets(int orientation) {
        if (orientation == 0) {
            return this.mStartHorizontalWidgets;
        }
        if (orientation == 1) {
            return this.mStartVerticalWidgets;
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    public Set<ConstraintWidget> getWidgetsToSet(int orientation) {
        if (orientation == 0) {
            return this.mWidgetsToSetHorizontal;
        }
        if (orientation == 1) {
            return this.mWidgetsToSetVertical;
        }
        return null;
    }

    /* access modifiers changed from: package-private */
    public void addWidgetsToSet(ConstraintWidget widget, int orientation) {
        if (orientation == 0) {
            this.mWidgetsToSetHorizontal.add(widget);
        } else if (orientation == 1) {
            this.mWidgetsToSetVertical.add(widget);
        }
    }

    /* access modifiers changed from: package-private */
    public List<ConstraintWidget> getWidgetsToSolve() {
        if (!this.mWidgetsToSolve.isEmpty()) {
            return this.mWidgetsToSolve;
        }
        int size = this.mConstrainedGroup.size();
        for (int i = 0; i < size; i++) {
            ConstraintWidget widget = this.mConstrainedGroup.get(i);
            if (!widget.mOptimizerMeasurable) {
                getWidgetsToSolveTraversal((ArrayList) this.mWidgetsToSolve, widget);
            }
        }
        this.mUnresolvedWidgets.clear();
        this.mUnresolvedWidgets.addAll(this.mConstrainedGroup);
        this.mUnresolvedWidgets.removeAll(this.mWidgetsToSolve);
        return this.mWidgetsToSolve;
    }

    private void getWidgetsToSolveTraversal(ArrayList<ConstraintWidget> widgetsToSolve, ConstraintWidget widget) {
        if (!widget.mGroupsToSolver) {
            widgetsToSolve.add(widget);
            widget.mGroupsToSolver = true;
            if (!widget.isFullyResolved()) {
                if (widget instanceof Helper) {
                    Helper helper = (Helper) widget;
                    int widgetCount = helper.mWidgetsCount;
                    for (int i = 0; i < widgetCount; i++) {
                        getWidgetsToSolveTraversal(widgetsToSolve, helper.mWidgets[i]);
                    }
                }
                int count = widget.mListAnchors.length;
                for (int i2 = 0; i2 < count; i2++) {
                    ConstraintAnchor targetAnchor = widget.mListAnchors[i2].mTarget;
                    if (targetAnchor != null) {
                        ConstraintWidget targetWidget = targetAnchor.mOwner;
                        if (!(targetAnchor == null || targetWidget == widget.getParent())) {
                            getWidgetsToSolveTraversal(widgetsToSolve, targetWidget);
                        }
                    }
                }
            }
        }
    }

    /* access modifiers changed from: package-private */
    public void updateUnresolvedWidgets() {
        int size = this.mUnresolvedWidgets.size();
        for (int i = 0; i < size; i++) {
            updateResolvedDimension(this.mUnresolvedWidgets.get(i));
        }
    }

    private void updateResolvedDimension(ConstraintWidget widget) {
        ConstraintAnchor targetAnchor;
        int end;
        ConstraintAnchor targetAnchor2;
        int end2;
        int end3 = 0;
        if (widget.mOptimizerMeasurable && !widget.isFullyResolved()) {
            boolean bottomSide = false;
            boolean rightSide = widget.mRight.mTarget != null;
            if (rightSide) {
                targetAnchor = widget.mRight.mTarget;
            } else {
                targetAnchor = widget.mLeft.mTarget;
            }
            if (targetAnchor != null) {
                if (!targetAnchor.mOwner.mOptimizerMeasured) {
                    updateResolvedDimension(targetAnchor.mOwner);
                }
                if (targetAnchor.mType == ConstraintAnchor.Type.RIGHT) {
                    end3 = targetAnchor.mOwner.mX + targetAnchor.mOwner.getWidth();
                } else if (targetAnchor.mType == ConstraintAnchor.Type.LEFT) {
                    end3 = targetAnchor.mOwner.mX;
                }
            }
            if (rightSide) {
                end = end3 - widget.mRight.getMargin();
            } else {
                end = end3 + widget.mLeft.getMargin() + widget.getWidth();
            }
            widget.setHorizontalDimension(end - widget.getWidth(), end);
            if (widget.mBaseline.mTarget != null) {
                ConstraintAnchor targetAnchor3 = widget.mBaseline.mTarget;
                if (!targetAnchor3.mOwner.mOptimizerMeasured) {
                    updateResolvedDimension(targetAnchor3.mOwner);
                }
                int start = (targetAnchor3.mOwner.mY + targetAnchor3.mOwner.mBaselineDistance) - widget.mBaselineDistance;
                widget.setVerticalDimension(start, widget.mHeight + start);
                widget.mOptimizerMeasured = true;
                return;
            }
            if (widget.mBottom.mTarget != null) {
                bottomSide = true;
            }
            if (bottomSide) {
                targetAnchor2 = widget.mBottom.mTarget;
            } else {
                targetAnchor2 = widget.mTop.mTarget;
            }
            if (targetAnchor2 != null) {
                if (!targetAnchor2.mOwner.mOptimizerMeasured) {
                    updateResolvedDimension(targetAnchor2.mOwner);
                }
                if (targetAnchor2.mType == ConstraintAnchor.Type.BOTTOM) {
                    end = targetAnchor2.mOwner.mY + targetAnchor2.mOwner.getHeight();
                } else if (targetAnchor2.mType == ConstraintAnchor.Type.TOP) {
                    end = targetAnchor2.mOwner.mY;
                }
            }
            if (bottomSide) {
                end2 = end - widget.mBottom.getMargin();
            } else {
                end2 = end + widget.mTop.getMargin() + widget.getHeight();
            }
            widget.setVerticalDimension(end2 - widget.getHeight(), end2);
            widget.mOptimizerMeasured = true;
        }
    }
}
