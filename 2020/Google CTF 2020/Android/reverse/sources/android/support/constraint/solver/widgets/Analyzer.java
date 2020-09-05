package android.support.constraint.solver.widgets;

import android.support.constraint.solver.widgets.ConstraintAnchor;
import android.support.constraint.solver.widgets.ConstraintWidget;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class Analyzer {
    private Analyzer() {
    }

    public static void determineGroups(ConstraintWidgetContainer layoutWidget) {
        if ((layoutWidget.getOptimizationLevel() & 32) != 32) {
            singleGroup(layoutWidget);
            return;
        }
        layoutWidget.mSkipSolver = true;
        layoutWidget.mGroupsWrapOptimized = false;
        layoutWidget.mHorizontalWrapOptimized = false;
        layoutWidget.mVerticalWrapOptimized = false;
        List<ConstraintWidget> widgets = layoutWidget.mChildren;
        List<ConstraintWidgetGroup> widgetGroups = layoutWidget.mWidgetGroups;
        boolean horizontalWrapContent = layoutWidget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
        boolean verticalWrapContent = layoutWidget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT;
        boolean hasWrapContent = horizontalWrapContent || verticalWrapContent;
        widgetGroups.clear();
        for (ConstraintWidget widget : widgets) {
            widget.mBelongingGroup = null;
            widget.mGroupsToSolver = false;
            widget.resetResolutionNodes();
        }
        for (ConstraintWidget widget2 : widgets) {
            if (widget2.mBelongingGroup == null && !determineGroups(widget2, widgetGroups, hasWrapContent)) {
                singleGroup(layoutWidget);
                layoutWidget.mSkipSolver = false;
                return;
            }
        }
        int measuredWidth = 0;
        int measuredHeight = 0;
        for (ConstraintWidgetGroup group : widgetGroups) {
            measuredWidth = Math.max(measuredWidth, getMaxDimension(group, 0));
            measuredHeight = Math.max(measuredHeight, getMaxDimension(group, 1));
        }
        if (horizontalWrapContent) {
            layoutWidget.setHorizontalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
            layoutWidget.setWidth(measuredWidth);
            layoutWidget.mGroupsWrapOptimized = true;
            layoutWidget.mHorizontalWrapOptimized = true;
            layoutWidget.mWrapFixedWidth = measuredWidth;
        }
        if (verticalWrapContent) {
            layoutWidget.setVerticalDimensionBehaviour(ConstraintWidget.DimensionBehaviour.FIXED);
            layoutWidget.setHeight(measuredHeight);
            layoutWidget.mGroupsWrapOptimized = true;
            layoutWidget.mVerticalWrapOptimized = true;
            layoutWidget.mWrapFixedHeight = measuredHeight;
        }
        setPosition(widgetGroups, 0, layoutWidget.getWidth());
        setPosition(widgetGroups, 1, layoutWidget.getHeight());
    }

    private static boolean determineGroups(ConstraintWidget widget, List<ConstraintWidgetGroup> widgetGroups, boolean hasWrapContent) {
        ConstraintWidgetGroup traverseList = new ConstraintWidgetGroup(new ArrayList(), true);
        widgetGroups.add(traverseList);
        return traverse(widget, traverseList, widgetGroups, hasWrapContent);
    }

    private static boolean traverse(ConstraintWidget widget, ConstraintWidgetGroup upperGroup, List<ConstraintWidgetGroup> widgetGroups, boolean hasWrapContent) {
        if (widget == null) {
            return true;
        }
        widget.mOptimizerMeasured = false;
        ConstraintWidgetContainer layoutWidget = (ConstraintWidgetContainer) widget.getParent();
        if (widget.mBelongingGroup == null) {
            widget.mOptimizerMeasurable = true;
            upperGroup.mConstrainedGroup.add(widget);
            widget.mBelongingGroup = upperGroup;
            if (widget.mLeft.mTarget == null && widget.mRight.mTarget == null && widget.mTop.mTarget == null && widget.mBottom.mTarget == null && widget.mBaseline.mTarget == null && widget.mCenter.mTarget == null) {
                invalidate(layoutWidget, widget, upperGroup);
                if (hasWrapContent) {
                    return false;
                }
            }
            if (!(widget.mTop.mTarget == null || widget.mBottom.mTarget == null)) {
                if (layoutWidget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                }
                if (hasWrapContent) {
                    invalidate(layoutWidget, widget, upperGroup);
                    return false;
                } else if (!(widget.mTop.mTarget.mOwner == widget.getParent() && widget.mBottom.mTarget.mOwner == widget.getParent())) {
                    invalidate(layoutWidget, widget, upperGroup);
                }
            }
            if (!(widget.mLeft.mTarget == null || widget.mRight.mTarget == null)) {
                if (layoutWidget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.WRAP_CONTENT) {
                }
                if (hasWrapContent) {
                    invalidate(layoutWidget, widget, upperGroup);
                    return false;
                } else if (!(widget.mLeft.mTarget.mOwner == widget.getParent() && widget.mRight.mTarget.mOwner == widget.getParent())) {
                    invalidate(layoutWidget, widget, upperGroup);
                }
            }
            if (((widget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) ^ (widget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT)) && widget.mDimensionRatio != 0.0f) {
                resolveDimensionRatio(widget);
            } else if (widget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT || widget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
                invalidate(layoutWidget, widget, upperGroup);
                if (hasWrapContent) {
                    return false;
                }
            }
            if (((widget.mLeft.mTarget == null && widget.mRight.mTarget == null) || ((widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner == widget.mParent && widget.mRight.mTarget == null) || ((widget.mRight.mTarget != null && widget.mRight.mTarget.mOwner == widget.mParent && widget.mLeft.mTarget == null) || (widget.mLeft.mTarget != null && widget.mLeft.mTarget.mOwner == widget.mParent && widget.mRight.mTarget != null && widget.mRight.mTarget.mOwner == widget.mParent)))) && widget.mCenter.mTarget == null && !(widget instanceof Guideline) && !(widget instanceof Helper)) {
                upperGroup.mStartHorizontalWidgets.add(widget);
            }
            if (((widget.mTop.mTarget == null && widget.mBottom.mTarget == null) || ((widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner == widget.mParent && widget.mBottom.mTarget == null) || ((widget.mBottom.mTarget != null && widget.mBottom.mTarget.mOwner == widget.mParent && widget.mTop.mTarget == null) || (widget.mTop.mTarget != null && widget.mTop.mTarget.mOwner == widget.mParent && widget.mBottom.mTarget != null && widget.mBottom.mTarget.mOwner == widget.mParent)))) && widget.mCenter.mTarget == null && widget.mBaseline.mTarget == null && !(widget instanceof Guideline) && !(widget instanceof Helper)) {
                upperGroup.mStartVerticalWidgets.add(widget);
            }
            if (widget instanceof Helper) {
                invalidate(layoutWidget, widget, upperGroup);
                if (hasWrapContent) {
                    return false;
                }
                Helper hWidget = (Helper) widget;
                for (int widgetsCount = 0; widgetsCount < hWidget.mWidgetsCount; widgetsCount++) {
                    if (!traverse(hWidget.mWidgets[widgetsCount], upperGroup, widgetGroups, hasWrapContent)) {
                        return false;
                    }
                }
            }
            int anchorsSize = widget.mListAnchors.length;
            for (int i = 0; i < anchorsSize; i++) {
                ConstraintAnchor anchor = widget.mListAnchors[i];
                if (!(anchor.mTarget == null || anchor.mTarget.mOwner == widget.getParent())) {
                    if (anchor.mType == ConstraintAnchor.Type.CENTER) {
                        invalidate(layoutWidget, widget, upperGroup);
                        if (hasWrapContent) {
                            return false;
                        }
                    } else {
                        setConnection(anchor);
                    }
                    if (!traverse(anchor.mTarget.mOwner, upperGroup, widgetGroups, hasWrapContent)) {
                        return false;
                    }
                }
            }
            return true;
        }
        if (widget.mBelongingGroup != upperGroup) {
            upperGroup.mConstrainedGroup.addAll(widget.mBelongingGroup.mConstrainedGroup);
            upperGroup.mStartHorizontalWidgets.addAll(widget.mBelongingGroup.mStartHorizontalWidgets);
            upperGroup.mStartVerticalWidgets.addAll(widget.mBelongingGroup.mStartVerticalWidgets);
            if (!widget.mBelongingGroup.mSkipSolver) {
                upperGroup.mSkipSolver = false;
            }
            widgetGroups.remove(widget.mBelongingGroup);
            for (ConstraintWidget auxWidget : widget.mBelongingGroup.mConstrainedGroup) {
                auxWidget.mBelongingGroup = upperGroup;
            }
        }
        return true;
    }

    private static void invalidate(ConstraintWidgetContainer layoutWidget, ConstraintWidget widget, ConstraintWidgetGroup group) {
        group.mSkipSolver = false;
        layoutWidget.mSkipSolver = false;
        widget.mOptimizerMeasurable = false;
    }

    private static int getMaxDimension(ConstraintWidgetGroup group, int orientation) {
        int offset = orientation * 2;
        List<ConstraintWidget> startWidgets = group.getStartWidgets(orientation);
        int size = startWidgets.size();
        int dimension = 0;
        for (int i = 0; i < size; i++) {
            ConstraintWidget widget = startWidgets.get(i);
            dimension = Math.max(dimension, getMaxDimensionTraversal(widget, orientation, widget.mListAnchors[offset + 1].mTarget == null || !(widget.mListAnchors[offset].mTarget == null || widget.mListAnchors[offset + 1].mTarget == null), 0));
        }
        group.mGroupDimensions[orientation] = dimension;
        return dimension;
    }

    /* JADX INFO: Multiple debug info for r3v2 int: [D('downDepth' int), D('dimension' int)] */
    /* JADX INFO: Multiple debug info for r6v26 android.support.constraint.solver.widgets.ResolutionAnchor: [D('dimensionPost' int), D('anchor' android.support.constraint.solver.widgets.ResolutionAnchor)] */
    private static int getMaxDimensionTraversal(ConstraintWidget widget, int orientation, boolean topLeftFlow, int depth) {
        int endOffset;
        int startOffset;
        int baselinePostDistance;
        int baselinePreDistance;
        int flow;
        int depth2;
        int dimensionPost;
        int postTemp;
        int startOffset2;
        ConstraintWidget parent;
        int postTemp2;
        boolean hasBaseline = false;
        if (!widget.mOptimizerMeasurable) {
            return 0;
        }
        int dimensionPre = 0;
        int dimensionPost2 = 0;
        if (widget.mBaseline.mTarget != null && orientation == 1) {
            hasBaseline = true;
        }
        if (topLeftFlow) {
            baselinePreDistance = widget.getBaselineDistance();
            baselinePostDistance = widget.getHeight() - widget.getBaselineDistance();
            startOffset = orientation * 2;
            endOffset = startOffset + 1;
        } else {
            baselinePreDistance = widget.getHeight() - widget.getBaselineDistance();
            baselinePostDistance = widget.getBaselineDistance();
            endOffset = orientation * 2;
            startOffset = endOffset + 1;
        }
        if (widget.mListAnchors[endOffset].mTarget == null || widget.mListAnchors[startOffset].mTarget != null) {
            flow = 1;
        } else {
            flow = -1;
            startOffset = endOffset;
            endOffset = startOffset;
        }
        if (hasBaseline) {
            depth2 = depth - baselinePreDistance;
        } else {
            depth2 = depth;
        }
        int dimension = (widget.mListAnchors[startOffset].getMargin() * flow) + getParentBiasOffset(widget, orientation);
        int dimension2 = dimension + depth2;
        int postTemp3 = (orientation == 0 ? widget.getWidth() : widget.getHeight()) * flow;
        for (Iterator it = widget.mListAnchors[startOffset].getResolutionNode().dependents.iterator(); it.hasNext(); it = it) {
            dimensionPre = Math.max(dimensionPre, getMaxDimensionTraversal(((ResolutionAnchor) ((ResolutionNode) it.next())).myAnchor.mOwner, orientation, topLeftFlow, dimension2));
            dimensionPost2 = dimensionPost2;
        }
        Iterator it2 = widget.mListAnchors[endOffset].getResolutionNode().dependents.iterator();
        int dimensionPost3 = dimensionPost2;
        while (it2.hasNext()) {
            dimensionPost3 = Math.max(dimensionPost3, getMaxDimensionTraversal(((ResolutionAnchor) ((ResolutionNode) it2.next())).myAnchor.mOwner, orientation, topLeftFlow, postTemp3 + dimension2));
            it2 = it2;
            endOffset = endOffset;
        }
        if (hasBaseline) {
            dimensionPre -= baselinePreDistance;
            dimensionPost = dimensionPost3 + baselinePostDistance;
        } else {
            dimensionPost = dimensionPost3 + ((orientation == 0 ? widget.getWidth() : widget.getHeight()) * flow);
        }
        int dimensionBaseline = 0;
        if (orientation == 1) {
            Iterator it3 = widget.mBaseline.getResolutionNode().dependents.iterator();
            while (it3.hasNext()) {
                ResolutionAnchor anchor = (ResolutionAnchor) ((ResolutionNode) it3.next());
                if (flow == 1) {
                    postTemp2 = postTemp3;
                    dimensionBaseline = Math.max(dimensionBaseline, getMaxDimensionTraversal(anchor.myAnchor.mOwner, orientation, topLeftFlow, baselinePreDistance + dimension2));
                } else {
                    postTemp2 = postTemp3;
                    dimensionBaseline = Math.max(dimensionBaseline, getMaxDimensionTraversal(anchor.myAnchor.mOwner, orientation, topLeftFlow, (baselinePostDistance * flow) + dimension2));
                }
                it3 = it3;
                startOffset = startOffset;
                postTemp3 = postTemp2;
            }
            startOffset2 = startOffset;
            postTemp = postTemp3;
            if (widget.mBaseline.getResolutionNode().dependents.size() > 0 && !hasBaseline) {
                if (flow == 1) {
                    dimensionBaseline += baselinePreDistance;
                } else {
                    dimensionBaseline -= baselinePostDistance;
                }
            }
        } else {
            startOffset2 = startOffset;
            postTemp = postTemp3;
        }
        int dimension3 = dimension + Math.max(dimensionPre, Math.max(dimensionPost, dimensionBaseline));
        int leftTop = depth2 + dimension;
        int end = leftTop + postTemp;
        if (flow == -1) {
            end = leftTop;
            leftTop = end;
        }
        if (topLeftFlow) {
            Optimizer.setOptimizedWidget(widget, orientation, leftTop);
            widget.setFrame(leftTop, end, orientation);
        } else {
            widget.mBelongingGroup.addWidgetsToSet(widget, orientation);
            widget.setRelativePositioning(leftTop, orientation);
        }
        if (widget.getDimensionBehaviour(orientation) == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT && widget.mDimensionRatio != 0.0f) {
            widget.mBelongingGroup.addWidgetsToSet(widget, orientation);
        }
        if (widget.mListAnchors[startOffset2].mTarget != null && widget.mListAnchors[endOffset].mTarget != null && widget.mListAnchors[startOffset2].mTarget.mOwner == (parent = widget.getParent()) && widget.mListAnchors[endOffset].mTarget.mOwner == parent) {
            widget.mBelongingGroup.addWidgetsToSet(widget, orientation);
        }
        return dimension3;
    }

    private static void setConnection(ConstraintAnchor originAnchor) {
        ResolutionNode originNode = originAnchor.getResolutionNode();
        if (originAnchor.mTarget != null && originAnchor.mTarget.mTarget != originAnchor) {
            originAnchor.mTarget.getResolutionNode().addDependent(originNode);
        }
    }

    private static void singleGroup(ConstraintWidgetContainer layoutWidget) {
        layoutWidget.mWidgetGroups.clear();
        layoutWidget.mWidgetGroups.add(0, new ConstraintWidgetGroup(layoutWidget.mChildren));
    }

    public static void setPosition(List<ConstraintWidgetGroup> groups, int orientation, int containerLength) {
        int groupsSize = groups.size();
        for (int i = 0; i < groupsSize; i++) {
            for (ConstraintWidget widget : groups.get(i).getWidgetsToSet(orientation)) {
                if (widget.mOptimizerMeasurable) {
                    updateSizeDependentWidgets(widget, orientation, containerLength);
                }
            }
        }
    }

    private static void updateSizeDependentWidgets(ConstraintWidget widget, int orientation, int containerLength) {
        int offset = orientation * 2;
        ConstraintAnchor startAnchor = widget.mListAnchors[offset];
        ConstraintAnchor endAnchor = widget.mListAnchors[offset + 1];
        if ((startAnchor.mTarget == null || endAnchor.mTarget == null) ? false : true) {
            Optimizer.setOptimizedWidget(widget, orientation, getParentBiasOffset(widget, orientation) + startAnchor.getMargin());
        } else if (widget.mDimensionRatio == 0.0f || widget.getDimensionBehaviour(orientation) != ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            int end = containerLength - widget.getRelativePositioning(orientation);
            int start = end - widget.getLength(orientation);
            widget.setFrame(start, end, orientation);
            Optimizer.setOptimizedWidget(widget, orientation, start);
        } else {
            int length = resolveDimensionRatio(widget);
            int start2 = (int) widget.mListAnchors[offset].getResolutionNode().resolvedOffset;
            endAnchor.getResolutionNode().resolvedTarget = startAnchor.getResolutionNode();
            endAnchor.getResolutionNode().resolvedOffset = (float) length;
            endAnchor.getResolutionNode().state = 1;
            widget.setFrame(start2, start2 + length, orientation);
        }
    }

    private static int getParentBiasOffset(ConstraintWidget widget, int orientation) {
        int offset = orientation * 2;
        ConstraintAnchor startAnchor = widget.mListAnchors[offset];
        ConstraintAnchor endAnchor = widget.mListAnchors[offset + 1];
        if (startAnchor.mTarget == null || startAnchor.mTarget.mOwner != widget.mParent || endAnchor.mTarget == null || endAnchor.mTarget.mOwner != widget.mParent) {
            return 0;
        }
        return (int) (((float) (((widget.mParent.getLength(orientation) - startAnchor.getMargin()) - endAnchor.getMargin()) - widget.getLength(orientation))) * (orientation == 0 ? widget.mHorizontalBiasPercent : widget.mVerticalBiasPercent));
    }

    private static int resolveDimensionRatio(ConstraintWidget widget) {
        int length;
        int length2 = -1;
        if (widget.getHorizontalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            if (widget.mDimensionRatioSide == 0) {
                length2 = (int) (((float) widget.getHeight()) * widget.mDimensionRatio);
            } else {
                length2 = (int) (((float) widget.getHeight()) / widget.mDimensionRatio);
            }
            widget.setWidth(length2);
        } else if (widget.getVerticalDimensionBehaviour() == ConstraintWidget.DimensionBehaviour.MATCH_CONSTRAINT) {
            if (widget.mDimensionRatioSide == 1) {
                length = (int) (((float) widget.getWidth()) * widget.mDimensionRatio);
            } else {
                length = (int) (((float) widget.getWidth()) / widget.mDimensionRatio);
            }
            widget.setHeight(length2);
        }
        return length2;
    }
}
