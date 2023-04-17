/**
 *
 * @file: filter_tree.cpp
 * @date: 16.04.2023
 */

#include "filter_tree.h"

FilterTree::FilterTree(FILTER_TREE_TYPE type) : type(type) {}

FilterTree::FilterTree(std::string *filter) : type(FILTER_TREE_TYPE_FILTER), filter(filter) {}

FilterTree::FilterTree(FILTER_TREE_TYPE type, std::string *filter) : type(type), filter(filter) {}

FilterTree::~FilterTree() {
    delete children;
    delete filter;
}

FILTER_TREE_TYPE FilterTree::get_type() const { return type; }

std::string *FilterTree::get_filter() const { return filter; }

void FilterTree::add_child(FilterTree *child) {
    if (children == nullptr) { children = new std::vector<FilterTree *>(); }

    children->push_back(child);
}

std::vector<FilterTree *> *FilterTree::get_children() const { return children; }

std::string FilterTree::generate_filter() {
    if (children != nullptr)
        for (auto *child: *children) { child->generate_filter(); }

    return process_current_node();
}

std::string FilterTree::process_current_node() {
    if (type == FILTER_TREE_TYPE_ROOT) { return ""; }

    if (type == FILTER_TREE_TYPE_FILTER) { return *filter; }

    if (type == FILTER_TREE_TYPE_AND) {
        std::string result = "(";

        if (children == nullptr) return "";

        for (auto *child: *children) {
            result.append(child->generate_filter());
            result.append(" and ");
        }

        result.pop_back();
        result.pop_back();
        result.pop_back();
        result.pop_back();
        result.pop_back();
        result.append(")");

        return result;
    }

    if (type == FILTER_TREE_TYPE_OR) {
        std::string result = "(";

        if (children == nullptr) return "";

        for (auto *child: *children) {
            result.append(child->generate_filter());
            result.append(" or ");
        }

        result.pop_back();
        result.pop_back();
        result.pop_back();
        result.append(")");

        return result;
    }

    return "";
}
